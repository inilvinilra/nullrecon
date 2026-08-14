package portscan

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type PortResult struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
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

func (e *Engine) WithConcurrency(n int) *Engine {
	if n > 0 {
		e.maxConcurrency = n
	}
	return e
}

func (e *Engine) WithDialTimeout(d time.Duration) *Engine {
	if d > 0 {
		e.dialTimeout = d
	}
	return e
}

func (e *Engine) WithAttempts(n int) *Engine {
	if n > 0 {
		e.dialAttempts = n
	}
	return e
}

func (e *Engine) Scan(ctx context.Context, target scopeguard.Target, ports []int) (HostResult, error) {
	res := HostResult{Target: firstNonEmpty(target.Host, target.IP)}
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
	pr.Open = true
	if e.grabBanners {
		conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
		buf := make([]byte, e.bannerBytes)
		n, _ := conn.Read(buf)
		conn.Close()
		if n > 0 {
			if v := mysqlVersion(buf[:n]); v != "" {
				pr.Service, pr.Version, pr.Banner = "mysql", v, "MySQL "+v
			} else {
				pr.Banner = sanitizeBanner(buf[:n])
				pr.Service, pr.Version = identifyService(port, pr.Banner)
			}
		} else {
			pr.Banner = e.serviceBanner(address, firstNonEmpty(target.Host, target.IP), port)
			pr.Service, pr.Version = identifyService(port, pr.Banner)
		}
	} else {
		conn.Close()
	}
	return pr
}

func mysqlVersion(raw []byte) string {
	if len(raw) < 6 || raw[4] != 0x0a {
		return ""
	}
	end := 5
	for end < len(raw) && raw[end] != 0x00 {
		end++
	}
	version := string(raw[5:end])
	if version == "" {
		return ""
	}
	for _, c := range version {
		if c < 32 || c > 126 {
			return ""
		}
	}
	if !strings.ContainsAny(version, "0123456789") {
		return ""
	}
	return version
}

func identifyService(port int, banner string) (service, version string) {
	switch {
	case strings.HasPrefix(banner, "SSH-"):
		fields := strings.SplitN(banner, "-", 3)
		if len(fields) < 3 {
			return "ssh", ""
		}
		rest := strings.TrimSpace(fields[2])
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			rest = rest[:sp]
		}
		return "ssh", strings.ReplaceAll(rest, "_", " ")
	case strings.HasPrefix(banner, "Redis "):
		return "redis", strings.TrimSpace(strings.TrimPrefix(banner, "Redis "))
	case banner == "PostgreSQL":
		return "postgresql", ""
	case strings.HasPrefix(banner, "HTTP/"):
		if i := strings.Index(banner, "| "); i >= 0 {
			return "http", strings.TrimSpace(banner[i+2:])
		}
		return "http", ""
	case strings.HasPrefix(banner, "220 ") || strings.HasPrefix(banner, "220-"):
		low := strings.ToLower(banner)
		if strings.Contains(low, "smtp") || strings.Contains(low, "esmtp") {
			return "smtp", firstToken(banner)
		}
		if strings.Contains(low, "ftp") {
			return "ftp", firstToken(banner)
		}
		return "", ""
	case strings.HasPrefix(banner, "* OK") && strings.Contains(strings.ToUpper(banner), "IMAP"):
		return "imap", ""
	case strings.HasPrefix(banner, "+OK") && strings.Contains(strings.ToUpper(banner), "POP"):
		return "pop3", ""
	}
	return "", ""
}

func firstToken(banner string) string {
	for _, f := range strings.Fields(banner) {
		if strings.ContainsAny(f, "0123456789.") && strings.ContainsAny(f, "0123456789") {
			if strings.Count(f, ".") >= 1 {
				return strings.Trim(f, "(),")
			}
		}
	}
	return ""
}

var redisVersionRe = regexp.MustCompile(`redis_version:([0-9][0-9.]*)`)

func (e *Engine) serviceBanner(address, host string, port int) string {
	for _, probe := range probeOrder(port) {
		conn, err := net.DialTimeout("tcp", address, e.dialTimeout)
		if err != nil {
			continue
		}
		var banner string
		switch probe {
		case "http":
			banner = e.probeHTTP(conn, host)
		case "redis":
			banner = e.probeRedis(conn)
		case "postgres":
			banner = e.probePostgres(conn)
		}
		conn.Close()
		if banner != "" {
			return banner
		}
	}
	return ""
}

func probeOrder(port int) []string {
	switch port {
	case 6379:
		return []string{"redis", "http"}
	case 5432:
		return []string{"postgres", "http"}
	case 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200:
		return []string{"http", "redis", "postgres"}
	default:
		return []string{"http", "redis", "postgres"}
	}
}

func (e *Engine) probeHTTP(conn net.Conn, host string) string {
	conn.SetWriteDeadline(e.now().Add(e.bannerTimeout))
	request := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: nullrecon/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return ""
	}
	conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 || !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		return ""
	}
	return httpBannerFrom(buf[:n])
}

func (e *Engine) probeRedis(conn net.Conn) string {
	conn.SetWriteDeadline(e.now().Add(e.bannerTimeout))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return ""
	}
	conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	reply := string(buf[:n])
	if n == 0 || !(strings.HasPrefix(reply, "+PONG") || strings.Contains(reply, "NOAUTH") || strings.Contains(reply, "operation not permitted") || strings.Contains(reply, "wrong number of arguments")) {
		return ""
	}
	conn.SetWriteDeadline(e.now().Add(e.bannerTimeout))
	if _, err := conn.Write([]byte("INFO server\r\n")); err == nil {
		conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
		info := make([]byte, 2048)
		m, _ := conn.Read(info)
		if version := redisVersionRe.FindStringSubmatch(string(info[:m])); len(version) == 2 {
			return "Redis " + version[1]
		}
	}
	return "Redis"
}

func (e *Engine) probePostgres(conn net.Conn) string {
	conn.SetWriteDeadline(e.now().Add(e.bannerTimeout))
	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslRequest); err != nil {
		return ""
	}
	conn.SetReadDeadline(e.now().Add(e.bannerTimeout))
	buf := make([]byte, 1)
	n, _ := conn.Read(buf)
	if n == 1 && (buf[0] == 'S' || buf[0] == 'N') {
		return "PostgreSQL"
	}
	return ""
}

func httpBannerFrom(raw []byte) string {
	text := string(raw)
	if !strings.HasPrefix(text, "HTTP/") {
		return sanitizeBanner(raw)
	}
	lines := strings.Split(text, "\n")
	statusLine := strings.TrimRight(lines[0], "\r")
	var server string
	for _, line := range lines[1:] {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break
		}
		if key, value, ok := strings.Cut(trimmed, ":"); ok && strings.EqualFold(strings.TrimSpace(key), "Server") {
			server = strings.TrimSpace(value)
			break
		}
	}
	if server != "" {
		return sanitizeBanner([]byte(statusLine + " | " + server))
	}
	return sanitizeBanner([]byte(statusLine))
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
