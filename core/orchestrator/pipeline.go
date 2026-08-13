package orchestrator

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/nullrecon/nullrecon/analysis/confidence"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/finding"
)

func (o *Orchestrator) collectLeakSignals(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	secrets, err := o.deps.DB.SecretCandidates().ForProject(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	byDetector := map[string]int{}
	for _, s := range secrets {
		byDetector[s.Detector]++
	}
	return out(map[string]any{"signals": len(secrets), "byDetector": byDetector})
}

func (o *Orchestrator) scanApprovedRepositories(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	return out(map[string]any{"repositories": 0, "note": "no approved repositories configured for this scope"})
}

func (o *Orchestrator) enrichVulnerabilities(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var plan struct {
		Targets []discoveryTarget `json:"targets"`
	}
	if err := inputAt(nc, "GenerateVulnerabilityCandidates", &plan); err != nil {
		return out(map[string]any{"enriched": 0})
	}
	return out(map[string]any{"candidates": len(plan.Targets), "note": "version-range intelligence pending vuln providers"})
}

func (o *Orchestrator) deduplicateSignals(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]int{}
	duplicates := 0
	for _, f := range findings {
		seen[f.FingerprintKey]++
		if seen[f.FingerprintKey] > 1 {
			duplicates++
		}
	}
	return out(map[string]any{"findings": len(findings), "unique": len(seen), "duplicates": duplicates})
}

func (o *Orchestrator) verifyCandidates(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	verified := 0
	for _, f := range findings {
		if f.Confidence.ActiveVerification >= 0.8 || f.Confidence.CrossSource >= 0.5 {
			verified++
		}
	}
	return out(map[string]any{"findings": len(findings), "verified": verified})
}

func (o *Orchestrator) scoreConfidence(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	model := confidence.DefaultModel()
	byState := map[string]int{}
	changed := 0
	for _, f := range findings {
		decision := model.Decide(f.Confidence, mandatoryFor(f))
		byState[string(decision.State)]++
		if f.State == decision.State && f.Confidence.Value == decision.Value {
			continue
		}
		f.State = decision.State
		f.Confidence.Value = decision.Value
		f.Confidence.Gates = mergeGates(f.Confidence.Gates, decision.Gates)
		if err := o.deps.DB.Findings().Upsert(ctx, f); err != nil {
			return nil, nil, err
		}
		changed++
	}
	return out(map[string]any{"scored": len(findings), "updated": changed, "byState": byState})
}

func (o *Orchestrator) prioritizeFindings(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := severityWeight(findings[i].Severity), severityWeight(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].Confidence.Value > findings[j].Confidence.Value
	})
	type ranked struct {
		ID       string  `json:"id"`
		Title    string  `json:"title"`
		Severity string  `json:"severity"`
		State    string  `json:"state"`
		Value    float64 `json:"value"`
	}
	top := make([]ranked, 0, len(findings))
	for _, f := range findings {
		if f.State == finding.StateFalsePositive || f.State == finding.StateOutOfScope || f.State == finding.StateDuplicate {
			continue
		}
		top = append(top, ranked{ID: f.ID, Title: f.Title, Severity: string(f.Severity), State: string(f.State), Value: f.Confidence.Value})
	}
	return out(map[string]any{"prioritized": len(top), "findings": top})
}

func (o *Orchestrator) buildEvidence(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	withEvidence := 0
	for _, f := range findings {
		if len(f.EvidenceIDs) > 0 || len(f.ObservationIDs) > 0 {
			withEvidence++
		}
	}
	return out(map[string]any{"findings": len(findings), "withEvidence": withEvidence})
}

func mandatoryFor(f finding.Finding) []string {
	return []string{"parse", "ownership"}
}

func mergeGates(existing, added []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range existing {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, g := range added {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func severityWeight(s finding.Severity) int {
	switch s {
	case finding.SevCritical:
		return 5
	case finding.SevHigh:
		return 4
	case finding.SevMedium:
		return 3
	case finding.SevLow:
		return 2
	case finding.SevInfo:
		return 1
	}
	return 0
}
