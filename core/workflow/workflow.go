package workflow

import (
	"fmt"
	"sort"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/policy"
)

const BaselineVersion = "1.0.0"

type FailurePolicy string

const (
	FailAbort    FailurePolicy = "abort"
	FailContinue FailurePolicy = "continue"
	FailSkipDeps FailurePolicy = "skipdependents"
)

type Node struct {
	Name           string             `json:"name"`
	ScopeRequired  bool               `json:"scopeRequired"`
	SafetyClass    policy.ActionClass `json:"safetyClass"`
	EstRequests    int64              `json:"estRequests"`
	EstCredits     int64              `json:"estCredits"`
	TimeoutSeconds int                `json:"timeoutSeconds"`
	MaxAttempts    int                `json:"maxAttempts"`
	Idempotent     bool               `json:"idempotent"`
	EvidenceOutput bool               `json:"evidenceOutput"`
	FailurePolicy  FailurePolicy      `json:"failurePolicy"`
	DependsOn      []string           `json:"dependsOn,omitempty"`
}

type Workflow struct {
	contracts.Versioned
	Name    string `json:"name"`
	Version string `json:"version"`
	Nodes   []Node `json:"nodes"`
}

func (w Workflow) Validate() error {
	if w.Name == "" || w.Version == "" {
		return fmt.Errorf("workflow: name and version required")
	}
	names := map[string]bool{}
	for _, n := range w.Nodes {
		if names[n.Name] {
			return fmt.Errorf("workflow: duplicate node %s", n.Name)
		}
		names[n.Name] = true
		if n.SafetyClass != "" {
			if _, err := policy.ParseAction(string(n.SafetyClass)); err != nil {
				return fmt.Errorf("workflow: node %s: %w", n.Name, err)
			}
		}
		if n.MaxAttempts < 1 {
			return fmt.Errorf("workflow: node %s needs at least one attempt", n.Name)
		}
	}
	for _, n := range w.Nodes {
		for _, dep := range n.DependsOn {
			if !names[dep] {
				return fmt.Errorf("workflow: node %s depends on unknown node %s", n.Name, dep)
			}
			if dep == n.Name {
				return fmt.Errorf("workflow: node %s depends on itself", n.Name)
			}
		}
	}
	if _, err := w.TopoSort(); err != nil {
		return err
	}
	return nil
}

func (w Workflow) TopoSort() ([]Node, error) {
	indegree := map[string]int{}
	byName := map[string]Node{}
	for _, n := range w.Nodes {
		byName[n.Name] = n
		indegree[n.Name] = len(n.DependsOn)
	}
	var ready []string
	for name, d := range indegree {
		if d == 0 {
			ready = append(ready, name)
		}
	}
	sort.Strings(ready)
	var order []Node
	for len(ready) > 0 {
		name := ready[0]
		ready = ready[1:]
		order = append(order, byName[name])
		for _, n := range w.Nodes {
			for _, dep := range n.DependsOn {
				if dep == name {
					indegree[n.Name]--
					if indegree[n.Name] == 0 {
						ready = append(ready, n.Name)
						sort.Strings(ready)
					}
				}
			}
		}
	}
	if len(order) != len(w.Nodes) {
		return nil, fmt.Errorf("workflow: dependency cycle detected")
	}
	return order, nil
}

func Baseline() Workflow {
	n := func(name string, class policy.ActionClass, deps ...string) Node {
		return Node{
			Name:           name,
			ScopeRequired:  class != "",
			SafetyClass:    class,
			TimeoutSeconds: 300,
			MaxAttempts:    2,
			Idempotent:     true,
			FailurePolicy:  FailSkipDeps,
			DependsOn:      deps,
		}
	}
	passive := []Node{
		n("LoadProject", ""),
		n("CompileScope", "", "LoadProject"),
		n("CheckProviders", "", "CompileScope"),
		n("CollectPassive", policy.ActionPassiveIntel, "CheckProviders"),
		n("NormalizeAssets", "", "CollectPassive"),
		n("ResolveOwnership", "", "NormalizeAssets"),
		n("BuildAssetGraph", "", "ResolveOwnership"),
	}
	active := []Node{
		n("DiscoverSubdomains", policy.ActionDNSResolve, "BuildAssetGraph"),
		n("PlanSafeActive", "", "DiscoverSubdomains"),
		n("ProbeHosts", policy.ActionTCPConnect, "PlanSafeActive"),
		n("DiscoverServices", policy.ActionServiceProbe, "ProbeHosts"),
		n("FingerprintTechnologies", policy.ActionTechFingerprint, "DiscoverServices"),
		n("AssessDeception", "", "DiscoverServices"),
		n("PlanContentDiscovery", "", "FingerprintTechnologies", "AssessDeception"),
		n("RunContentDiscovery", policy.ActionContentDiscovery, "PlanContentDiscovery"),
		n("GenerateVulnerabilityCandidates", "", "FingerprintTechnologies"),
		n("RunAllowedChecks", policy.ActionVulnTemplate, "GenerateVulnerabilityCandidates"),
		n("CollectLeakSignals", policy.ActionPassiveIntel, "BuildAssetGraph"),
		n("ScanApprovedRepositories", policy.ActionPassiveIntel, "BuildAssetGraph"),
		n("EnrichVulnerabilities", policy.ActionPassiveIntel, "GenerateVulnerabilityCandidates"),
		n("DeduplicateSignals", "", "RunContentDiscovery", "RunAllowedChecks", "CollectLeakSignals", "ScanApprovedRepositories"),
		n("VerifyCandidates", policy.ActionVulnVerify, "DeduplicateSignals", "EnrichVulnerabilities"),
		n("ScoreConfidence", "", "VerifyCandidates"),
		n("PrioritizeFindings", "", "ScoreConfidence"),
		n("BuildEvidence", "", "PrioritizeFindings"),
		n("RenderReports", "", "BuildEvidence"),
	}
	w := Workflow{
		Versioned: contracts.Versioned{Kind: "workflow", Version: contracts.RuleSetV1},
		Name:      "baseline",
		Version:   BaselineVersion,
		Nodes:     append(passive, active...),
	}
	return w
}
