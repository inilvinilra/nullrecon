package subdomain

import (
	"context"
	"sort"
	"strings"

	"github.com/nullrecon/nullrecon/providers/registry"
)

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
	res := PassiveResult{Domain: domain, BySource: map[string]int{}, Sources: len(sources)}
	seen := map[string]bool{}
	q := registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": domain}}
	for _, source := range sources {
		out, err := e.Execute(ctx, source, q)
		if err != nil {
			if res.Errors == nil {
				res.Errors = map[string]string{}
			}
			res.Errors[source] = err.Error()
			continue
		}
		for _, rec := range out.Records {
			host := normalizeHost(rec.Value)
			if host == "" && rec.Kind == "hostname" {
				host = normalizeHost(rec.Fields["hostname"])
			}
			if !inScope(host, domain) {
				continue
			}
			res.BySource[source]++
			if !seen[host] {
				seen[host] = true
				res.Hostnames = append(res.Hostnames, host)
			}
		}
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
