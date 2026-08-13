package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type PortResult struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Banner  string `json:"banner,omitempty"`
	Latency string `json:"latency"`
	Error   string `json:"error,omitempty"`
}

type HostResult struct {
	Target  string       `json:"target"`
	Ports   []PortResult `json:"ports"`
	Blocked []int        `json:"blockedPorts,omitempty"`
}

type Engine struct {
	snapshot       scopeguard.Snapshot
	budget         *budgetguard.Guard
	dialTimeout    time.Duration
	bannerTimeout  time.Duration
	bannerBytes    int
	grabBanners    bool
	maxConcurrency int
	dialAttempts   int
	now            func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	return &Engine{
		snapshot:       snapshot,
		budget:         budget,
		dialTimeout:    3 * time.Second,
		bannerTimeout:  2 * time.Second,
		bannerBytes:    256,
		maxConcurrency: 32,
		dialAttempts:   2,
		now:            func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) WithBanners(enabled bool) *Engine {
	e.grabBanners = enabled
	return e
}

func (e *Engine) Scan(ctx context.Context, target scopeguard.Target, ports []int) (HostResult, error) {
	res := HostResult{Target: target.Host + target.IP}
	sem := make(chan struct{}, e.maxConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		candidate := target
		candidate.Port = port
		if candidate.Protocol == "" {
			candidate.Protocol = "tcp"
		}
		if d := e.snapshot.EvaluateAction(candidate, "tcpconnect", e.now()); !d.Allowed {
			res.Blocked = append(res.Blocked, port)
			continue
		}
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
				res.Blocked = append(res.Blocked, port)
				continue
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			pr := e.probe(ctx, target, port)
			mu.Lock()
			res.Ports = append(res.Ports, pr)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	for i := 1; i < len(res.Ports); i++ {
		for j := i; j > 0 && res.Ports[j].Port < res.Ports[j-1].Port; j-- {
			res.Ports[j], res.Ports[j-1] = res.Ports[j-1], res.Ports[j]
		}
	}
	return res, nil
}

func (e *Engine) probe(ctx context.Context, target scopeguard.Target, port int) PortResult {
	start := e.now()
	pr := PortResult{Port: port}
	address := net.JoinHostPort(firstNonEmpty(target.Host, target.IP), fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error
	for attempt := 0; attempt < e.dialAttempts; attempt++ {
		conn, err = net.DialTimeout("tcp", address, e.dialTimeout)
		if err == nil {
			break
		}
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			continue
		}
		break
	}
	pr.Latency = e.now().Sub(start).Round(time.Millisecond).String()
	if err != nil {
		pr.Error = "closed-or-filtered"
		return pr
	}
	defer conn.Close()
	pr.Open = true
	if e.grabBanners {
		conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
		buf := make([]byte, e.bannerBytes)
		n, _ := conn.Read(buf)
		if n > 0 {
			pr.Banner = sanitizeBanner(buf[:n])
		}
	}
	return pr
}

func sanitizeBanner(raw []byte) string {
	out := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b >= 32 && b < 127 {
			out = append(out, b)
		} else if b == '\n' || b == '\r' {
			break
		}
	}
	return string(out)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
