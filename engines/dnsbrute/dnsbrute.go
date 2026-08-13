package dnsbrute

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Result struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips"`
	CNAME  string   `json:"cname,omitempty"`
	Source string   `json:"source"`
}

type Options struct {
	Concurrency int
	PerLookup   time.Duration
	Words       []string
}

type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	resolver hostResolver
	now      func() time.Time
}

var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "8.8.4.4:53"}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	var idx uint32
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			n := atomic.AddUint32(&idx, 1)
			server := publicResolvers[int(n)%len(publicResolvers)]
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		resolver: resolver,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) WithResolver(r hostResolver) *Engine {
	e.resolver = r
	return e
}

type Summary struct {
	Domain   string   `json:"domain"`
	Tested   int      `json:"tested"`
	Resolved int      `json:"resolved"`
	Blocked  int      `json:"blocked"`
	Results  []Result `json:"results"`
}

func (e *Engine) Discover(ctx context.Context, domain string, opts Options) (Summary, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	words := opts.Words
	if len(words) == 0 {
		words = DefaultWords()
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 20
	}
	perLookup := opts.PerLookup
	if perLookup <= 0 {
		perLookup = 3 * time.Second
	}

	candidates := make([]string, 0, len(words))
	seen := map[string]bool{}
	summary := Summary{Domain: domain}
	for _, w := range words {
		host := strings.ToLower(strings.TrimSpace(w)) + "." + domain
		if w == "" || seen[host] {
			continue
		}
		seen[host] = true
		if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: host}, "dnsresolve", e.now()); !d.Allowed {
			summary.Blocked++
			continue
		}
		candidates = append(candidates, host)
	}

	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if e.budget != nil {
					if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
						continue
					}
				}
				res, ok := e.resolve(ctx, host, perLookup)
				mu.Lock()
				summary.Tested++
				if ok {
					summary.Results = append(summary.Results, res)
				}
				mu.Unlock()
			}
		}()
	}
	for _, host := range candidates {
		select {
		case <-ctx.Done():
		case jobs <- host:
		}
	}
	close(jobs)
	wg.Wait()

	summary.Resolved = len(summary.Results)
	sort.Slice(summary.Results, func(i, j int) bool { return summary.Results[i].Host < summary.Results[j].Host })
	return summary, nil
}

func (e *Engine) resolve(ctx context.Context, host string, timeout time.Duration) (Result, bool) {
	var addrs []string
	for attempt := 0; attempt < 3; attempt++ {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		found, err := e.resolver.LookupHost(lctx, host)
		cancel()
		if err == nil && len(found) > 0 {
			addrs = found
			break
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return Result{}, false
		}
	}
	if len(addrs) == 0 {
		return Result{}, false
	}
	ips := uniqueSorted(addrs)
	res := Result{Host: host, IPs: ips, Source: "dnsbrute"}
	cctx, ccancel := context.WithTimeout(ctx, timeout)
	defer ccancel()
	if cname, cerr := e.resolver.LookupCNAME(cctx, host); cerr == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != host {
			res.CNAME = cname
		}
	}
	return res, true
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
