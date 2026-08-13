package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nullrecon/nullrecon/analysis/correlate"
	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/service"
	"github.com/nullrecon/nullrecon/engines/fingerprint"
	"github.com/nullrecon/nullrecon/engines/portscan"
	"github.com/nullrecon/nullrecon/engines/template"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/platform/objectstore"
	"github.com/nullrecon/nullrecon/providers/registry"
)

type Deps struct {
	DB           *database.DB
	Registry     *registry.Registry
	Executor     *registry.Executor
	Raw          *objectstore.Store
	Fingerprints *fingerprint.Engine
}

type Orchestrator struct {
	deps            Deps
	now             func() time.Time
	tmplCVEResolver func() map[string]string
}

func New(deps Deps) *Orchestrator {
	return &Orchestrator{
		deps:            deps,
		now:             func() time.Time { return time.Now().UTC() },
		tmplCVEResolver: defaultTemplateCVEs,
	}
}

func defaultTemplateCVEs() map[string]string {
	out := map[string]string{}
	if set, err := template.LoadEmbedded(); err == nil {
		for _, t := range set.Templates {
			if t.Info.CVE != "" {
				out[t.ID] = t.Info.CVE
			}
		}
	}
	return out
}

func (o *Orchestrator) RegisterAll(e *workflow.Engine) {
	e.Register("LoadProject", o.loadProject)
	e.Register("CompileScope", o.compileScope)
	e.Register("CheckProviders", o.checkProviders)
	e.Register("CollectPassive", o.collectPassive)
	e.Register("NormalizeAssets", o.normalizeAssets)
	e.Register("ResolveOwnership", o.resolveOwnership)
	e.Register("BuildAssetGraph", o.buildAssetGraph)
	e.Register("PlanSafeActive", o.planSafeActive)
	e.Register("ProbeHosts", o.probeHosts)
	e.Register("DiscoverServices", o.discoverServices)
	e.Register("FingerprintTechnologies", o.fingerprintTechnologies)
	e.Register("AssessDeception", o.assessDeception)
	e.Register("PlanContentDiscovery", o.planContentDiscovery)
	e.Register("RunContentDiscovery", o.runContentDiscovery)
	e.Register("GenerateVulnerabilityCandidates", o.generateVulnerabilityCandidates)
	e.Register("RunAllowedChecks", o.runAllowedChecks)
	e.Register("CollectLeakSignals", o.collectLeakSignals)
	e.Register("ScanApprovedRepositories", o.scanApprovedRepositories)
	e.Register("EnrichVulnerabilities", o.enrichVulnerabilities)
	e.Register("DeduplicateSignals", o.deduplicateSignals)
	e.Register("VerifyCandidates", o.verifyCandidates)
	e.Register("ScoreConfidence", o.scoreConfidence)
	e.Register("PrioritizeFindings", o.prioritizeFindings)
	e.Register("BuildEvidence", o.buildEvidence)
	e.Register("RenderReports", o.renderReports)
}

func out(v any) (json.RawMessage, []byte, error) {
	data, err := json.Marshal(v)
	return data, nil, err
}

func inputAt(nc *workflow.NodeContext, node string, v any) error {
	raw, ok := nc.Input[node]
	if !ok {
		return fmt.Errorf("orchestrator: missing input from %s", node)
	}
	return json.Unmarshal(raw, v)
}

func (o *Orchestrator) loadProject(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	project, err := o.deps.DB.Projects().Get(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	if project.Status != "active" {
		return nil, nil, fmt.Errorf("orchestrator: project %s is %s", project.ID, project.Status)
	}
	return out(map[string]string{"projectId": project.ID, "slug": project.Slug})
}

func (o *Orchestrator) compileScope(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	if nc.Snapshot.ID == "" || nc.Snapshot.Hash == "" {
		return nil, nil, fmt.Errorf("orchestrator: run requires a compiled scope snapshot")
	}
	if err := o.deps.DB.Snapshots().Put(ctx, nc.Snapshot); err != nil {
		return nil, nil, err
	}
	return out(map[string]string{"snapshotId": nc.Snapshot.ID, "snapshotHash": nc.Snapshot.Hash})
}

func (o *Orchestrator) checkProviders(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	type status struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
	}
	var outStatus []status
	if o.deps.Registry != nil {
		for _, d := range o.deps.Registry.Descriptors() {
			healthy := true
			if o.deps.Executor != nil {
				healthy = o.deps.Executor.Healthy(d.Name)
			}
			outStatus = append(outStatus, status{Name: d.Name, Healthy: healthy})
		}
	}
	return out(outStatus)
}

const maxPassiveRecords = 2000

func (o *Orchestrator) collectPassive(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	if o.deps.Registry == nil || o.deps.Executor == nil {
		return nil, nil, fmt.Errorf("orchestrator: providers not configured")
	}
	seeds := append(append([]string{}, nc.Snapshot.Scope.RootDomains...), nc.Snapshot.Scope.ExactDomains...)
	if len(seeds) == 0 {
		return out(map[string]any{"records": 0, "note": "no domain seeds in scope"})
	}
	var all []registry.Record
	var errs []string
	for _, seed := range seeds {
		for _, d := range o.deps.Registry.Descriptors() {
			if !o.deps.Executor.Healthy(d.Name) {
				continue
			}
			if len(all) >= maxPassiveRecords {
				break
			}
			var q registry.Query
			switch {
			case d.Supports(registry.CapSubdomainSearch):
				q = registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": seed}, Limit: 200}
			case d.Supports(registry.CapAssetSearch):
				q = registry.Query{Capability: registry.CapAssetSearch, Params: map[string]string{"q": fmt.Sprintf("domain=\"%s\"", seed)}, Limit: 200}
			default:
				continue
			}
			res, err := o.deps.Executor.Execute(ctx, d.Name, q)
			if err != nil {
				errs = append(errs, d.Name)
				continue
			}
			all = append(all, res.Records...)
		}
	}
	payload := map[string]any{"records": len(all), "providerErrors": errs}
	data, err := json.Marshal(struct {
		Summary map[string]any    `json:"summary"`
		Records []registry.Record `json:"records"`
	}{payload, all})
	return data, nil, err
}

func (o *Orchestrator) normalizeAssets(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var payload struct {
		Records []registry.Record `json:"records"`
	}
	if err := inputAt(nc, "CollectPassive", &payload); err != nil {
		return out(map[string]any{"assets": 0})
	}
	ing := correlate.NewIngestor(o.deps.DB, nc.Snapshot)
	stats, err := ing.Ingest(ctx, nc.Run.ProjectID, "passive", payload.Records)
	if err != nil {
		return nil, nil, err
	}
	return out(stats)
}

func (o *Orchestrator) resolveOwnership(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	assets, err := o.deps.DB.Assets().List(ctx, nc.Run.ProjectID, "")
	if err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	for _, a := range assets {
		counts[string(a.Class)]++
	}
	return out(counts)
}

func (o *Orchestrator) buildAssetGraph(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	assets, err := o.deps.DB.Assets().List(ctx, nc.Run.ProjectID, "")
	if err != nil {
		return nil, nil, err
	}
	relations := 0
	for _, a := range assets {
		rels, err := o.deps.DB.Assets().Relations(ctx, a.ID)
		if err != nil {
			return nil, nil, err
		}
		relations += len(rels)
	}
	return out(map[string]int{"assets": len(assets), "relationEdges": relations / 2})
}

type probeTarget struct {
	AssetID string `json:"assetId"`
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Ports   []int  `json:"ports"`
}

func (o *Orchestrator) planSafeActive(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	if !nc.Snapshot.Mode.Allows(policy.ModeSafeActive) {
		return out(map[string]any{"targets": []probeTarget{}, "note": "mode does not permit active probing"})
	}
	assets, err := o.deps.DB.Assets().List(ctx, nc.Run.ProjectID, "")
	if err != nil {
		return nil, nil, err
	}
	ports := nc.Snapshot.Scope.Ports
	var targets []probeTarget
	for _, a := range assets {
		if a.Class != asset.ClassActive || len(ports) == 0 {
			continue
		}
		t := probeTarget{AssetID: a.ID, Ports: ports}
		switch a.Kind {
		case asset.KindIP:
			t.IP = a.Value
		case asset.KindHostname, asset.KindDomain:
			t.Host = a.Value
		default:
			continue
		}
		targets = append(targets, t)
	}
	return out(map[string]any{"targets": targets})
}

func (o *Orchestrator) probeHosts(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var plan struct {
		Targets []probeTarget `json:"targets"`
	}
	if err := inputAt(nc, "PlanSafeActive", &plan); err != nil {
		return nil, nil, err
	}
	engine := portscan.New(nc.Snapshot, nc.Budget)
	var open []map[string]any
	for _, target := range plan.Targets {
		res, err := engine.Scan(ctx, scopeguard.Target{Host: target.Host, IP: target.IP}, target.Ports)
		if err != nil {
			return nil, nil, err
		}
		for _, p := range res.Ports {
			if !p.Open {
				continue
			}
			svc := service.New(nc.Run.ProjectID, target.AssetID, "tcp", p.Port, "portscan", o.now())
			if p.Banner != "" {
				svc.BannerHash = contracts.HashBytes([]byte(p.Banner))
				svc.Attrs = map[string]string{"banner": p.Banner}
			}
			if err := o.deps.DB.Services().Upsert(ctx, svc); err != nil {
				return nil, nil, err
			}
			open = append(open, map[string]any{"assetId": target.AssetID, "host": firstOf(target.Host, target.IP), "port": p.Port, "banner": p.Banner})
		}
	}
	return out(map[string]any{"open": open})
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
