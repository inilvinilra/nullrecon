package orchestrator

import (
	"context"
	"encoding/json"

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
	var records []registry.Record
	tested := 0
	for _, domain := range seeds {
		summary, err := engine.Discover(ctx, domain, dnsbrute.Options{})
		if err != nil {
			continue
		}
		tested += summary.Tested
		for _, r := range summary.Results {
			rec := registry.Record{Kind: "hostname", Value: r.Host, Fields: map[string]string{"hostname": r.Host}}
			if len(r.IPs) > 0 {
				rec.Fields["ip"] = r.IPs[0]
			}
			records = append(records, rec)
		}
	}
	ing := correlate.NewIngestor(o.deps.DB, nc.Snapshot)
	stats, err := ing.Ingest(ctx, nc.Run.ProjectID, "dnsbrute", records)
	if err != nil {
		return nil, nil, err
	}
	return out(map[string]any{"seeds": len(seeds), "tested": tested, "discovered": len(records), "assets": stats.Assets})
}
