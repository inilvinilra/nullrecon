package subdomain

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const defaultOverallTimeout = 30 * time.Second

type Enumerator interface {
	Execute(ctx context.Context, name string, q registry.Query) (registry.Result, error)
}

type PassiveResult struct {
	Domain    string            `json:"domain"`
	Hostnames []string          `json:"hostnames"`
	BySource  map[string]int    `json:"bySource"`
	Errors    map[string]string `json:"errors,omitempty"`
	Sources   int               `json:"sources"`
}

func EnumeratePassive(ctx context.Context, e Enumerator, sources []string, domain string) PassiveResult {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "*.")))
	res := PassiveResult{Domain: domain, BySource: map[string]int{}, Errors: map[string]string{}, Sources: len(sources)}
	q := registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": domain}}

	ctx, cancel := context.WithTimeout(ctx, defaultOverallTimeout)
	defer cancel()

	type sourceResult struct {
		source string
		hosts  []string
		err    error
	}
	results := make(chan sourceResult, len(sources))
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(source string) {
			defer wg.Done()
			out, err := e.Execute(ctx, source, q)
			if err != nil {
				results <- sourceResult{source: source, err: err}
				return
			}
			var hosts []string
			for _, rec := range out.Records {
				host := normalizeHost(rec.Value)
				if host == "" && rec.Kind == "hostname" {
					host = normalizeHost(rec.Fields["hostname"])
				}
				if inScope(host, domain) {
					hosts = append(hosts, host)
				}
			}
			results <- sourceResult{source: source, hosts: hosts}
		}(source)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	seen := map[string]bool{}
	for r := range results {
		if r.err != nil {
			res.Errors[r.source] = r.err.Error()
			continue
		}
		for _, host := range r.hosts {
			res.BySource[r.source]++
			if !seen[host] {
				seen[host] = true
				res.Hostnames = append(res.Hostnames, host)
			}
		}
	}
	if len(res.Errors) == 0 {
		res.Errors = nil
	}
	sort.Strings(res.Hostnames)
	return res
}

func normalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	return host
}

func inScope(host, domain string) bool {
	if host == "" || strings.ContainsAny(host, " @/") {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

func SubdomainSources(reg *registry.Registry) []string {
	var names []string
	for _, d := range reg.Descriptors() {
		if d.Supports(registry.CapSubdomainSearch) {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return names
}
