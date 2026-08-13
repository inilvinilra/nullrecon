package renderer

import (
	"encoding/json"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/finding"
)

type Data struct {
	contracts.Versioned
	Title         string            `json:"title"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	ProjectID     string            `json:"projectId"`
	ProjectSlug   string            `json:"projectSlug"`
	RunID         string            `json:"runId,omitempty"`
	SnapshotHash  string            `json:"snapshotHash,omitempty"`
	Mode          string            `json:"mode,omitempty"`
	Findings      []finding.Finding `json:"findings"`
	SecretSummary map[string]int    `json:"secretSummary,omitempty"`
	ExposureCount int               `json:"exposureCount"`
}

func New(projectID, slug string, now time.Time) Data {
	return Data{
		Versioned:   contracts.Versioned{Kind: "report", Version: contracts.ReportV1},
		Title:       "nullrecon report",
		GeneratedAt: now.UTC(),
		ProjectID:   projectID,
		ProjectSlug: slug,
		Findings:    []finding.Finding{},
	}
}

func severityOrder(severity finding.Severity) int {
	switch severity {
	case finding.SevCritical:
		return 0
	case finding.SevHigh:
		return 1
	case finding.SevMedium:
		return 2
	case finding.SevLow:
		return 3
	case finding.SevInfo:
		return 4
	}
	return 5
}

func (d Data) SeverityCounts() map[string]int {
	counts := map[string]int{}
	for _, f := range d.Findings {
		counts[string(f.Severity)]++
	}
	return counts
}

func RenderJSON(d Data) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
