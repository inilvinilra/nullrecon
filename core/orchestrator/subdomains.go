package orchestrator

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nullrecon/nullrecon/analysis/correlate"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/engines/dnsbrute"
	"github.com/nullrecon/nullrecon/providers/registry"
)

func (o *Orchestrator) discoverSubdomains(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	seeds := append(append([]string{}, nc.Snapshot.Scope.RootDomains...), nc.Snapshot.Scope.ExactDomains...)
	if len(seeds) == 0 {
		return out(map[string]any{"discovered": 0, "note": "no domain seeds in scope"})
	}
	engine := dnsbrute.New(nc.Snapshot, nc.Budget)
	seenHost := map[string]bool{}
	var records []registry.Record
	tested := 0
	fromBrute := 0
	fromPassive := 0
	addResult := func(host string, ips []string, source string) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || seenHost[host] {
			return
		}
		seenHost[host] = true
		rec := registry.Record{Kind: "hostname", Value: host, Fields: map[string]string{"hostname": host}}
		if len(ips) > 0 {
			rec.Fields["ip"] = ips[0]
		}
		records = append(records, rec)
		if source == "brute" {
			fromBrute++
		} else {
			fromPassive++
		}
	}
	for _, domain := range seeds {
		summary, err := engine.Discover(ctx, domain, dnsbrute.Options{})
		if err == nil {
			tested += summary.Tested
			for _, r := range summary.Results {
				addResult(r.Host, r.IPs, "brute")
			}
		}
	}
	passiveCandidates := o.passiveSubdomains(ctx, seeds)
	if len(passiveCandidates) > 0 {
		verified := engine.Verify(ctx, passiveCandidates)
		for _, r := range verified.Results {
			addResult(r.Host, r.IPs, "passive")
		}
	}
	ing := correlate.NewIngestor(o.deps.DB, nc.Snapshot)
	stats, err := ing.Ingest(ctx, nc.Run.ProjectID, "subdomain", records)
	if err != nil {
		return nil, nil, err
	}
	return out(map[string]any{"seeds": len(seeds), "tested": tested, "fromBrute": fromBrute, "fromPassive": fromPassive, "discovered": len(records), "assets": stats.Assets})
}

func (o *Orchestrator) passiveSubdomains(ctx context.Context, seeds []string) []string {
	if o.deps.Registry == nil || o.deps.Executor == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range o.deps.Registry.Descriptors() {
		if !d.Supports(registry.CapSubdomainSearch) || !o.deps.Executor.Healthy(d.Name) {
			continue
		}
		for _, seed := range seeds {
			q := registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": seed}, Limit: 500}
			res, err := o.deps.Executor.Execute(ctx, d.Name, q)
			if err != nil {
				continue
			}
			for _, rec := range res.Records {
				host := rec.Value
				if host == "" {
					host = rec.Fields["hostname"]
				}
				host = strings.ToLower(strings.TrimSpace(host))
				if host == "" || seen[host] || !strings.HasSuffix(host, "."+seed) {
					continue
				}
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	return out
}
