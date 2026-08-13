package workflow

import (
	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type NodePlan struct {
	Name        string   `json:"name"`
	SafetyClass string   `json:"safetyClass"`
	EstRequests int64    `json:"estRequests"`
	EstCredits  int64    `json:"estCredits"`
	Allowed     bool     `json:"allowed"`
	Reasons     []string `json:"reasons"`
	DependsOn   []string `json:"dependsOn,omitempty"`
}

type PlanReport struct {
	Workflow      string                     `json:"workflow"`
	Version       string                     `json:"version"`
	SnapshotHash  string                     `json:"snapshotHash"`
	Mode          string                     `json:"mode"`
	Nodes         []NodePlan                 `json:"nodes"`
	TotalRequests int64                      `json:"totalRequests"`
	TotalCredits  int64                      `json:"totalCredits"`
	Budget        []budgetguard.PlanDecision `json:"budgetDecisions"`
	Executable    bool                       `json:"executable"`
}

func Plan(wf Workflow, snapshot scopeguard.Snapshot, budget *budgetguard.Guard) (PlanReport, error) {
	order, err := wf.TopoSort()
	if err != nil {
		return PlanReport{}, err
	}
	report := PlanReport{
		Workflow:     wf.Name,
		Version:      wf.Version,
		SnapshotHash: snapshot.Hash,
		Mode:         string(snapshot.Mode),
		Executable:   true,
	}
	for _, node := range order {
		np := NodePlan{
			Name:        node.Name,
			SafetyClass: string(node.SafetyClass),
			EstRequests: node.EstRequests,
			EstCredits:  node.EstCredits,
			DependsOn:   node.DependsOn,
		}
		if node.SafetyClass == "" {
			np.Allowed = true
			np.Reasons = []string{"no active capability required"}
		} else {
			granted := snapshot.Scope.Grants(string(node.SafetyClass))
			d := policy.Decide(snapshot.Mode, node.SafetyClass, granted)
			np.Allowed = d.Allowed
			np.Reasons = d.Reasons
			if snapshot.Scope.DeniesAction(string(node.SafetyClass)) {
				np.Allowed = false
				np.Reasons = append(np.Reasons, "action explicitly denied by scope")
			}
		}
		report.TotalRequests += node.EstRequests
		report.TotalCredits += node.EstCredits
		report.Nodes = append(report.Nodes, np)
	}
	if budget != nil {
		report.Budget = budget.Plan(budgetguard.Cost{Requests: report.TotalRequests, Credits: report.TotalCredits})
		for _, d := range report.Budget {
			if !d.Allowed {
				report.Executable = false
			}
		}
	}
	return report, nil
}
