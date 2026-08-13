package renderer

import (
	"encoding/json"

	"github.com/nullrecon/nullrecon/domain/finding"
)

const sarifVersion = "2.1.0"

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Properties sarifResultProps `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResultProps struct {
	State        string   `json:"state"`
	Confidence   float64  `json:"confidence"`
	Severity     string   `json:"severity"`
	AssetIDs     []string `json:"assetIds,omitempty"`
	SnapshotHash string   `json:"snapshotHash,omitempty"`
}

func sarifLevel(severity finding.Severity) string {
	switch severity {
	case finding.SevCritical, finding.SevHigh:
		return "error"
	case finding.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func RenderSARIF(d Data) ([]byte, error) {
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range d.Findings {
		ruleID := f.WeaknessClass
		if ruleID == "" {
			ruleID = "finding"
		}
		if !ruleSeen[ruleID] {
			ruleSeen[ruleID] = true
			rules = append(rules, sarifRule{ID: ruleID, Name: ruleID})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title},
			Properties: sarifResultProps{
				State:        string(f.State),
				Confidence:   f.Confidence.Value,
				Severity:     string(f.Severity),
				AssetIDs:     f.AssetIDs,
				SnapshotHash: f.SnapshotHash,
			},
		})
	}
	if results == nil {
		results = []sarifResult{}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "nullrecon", Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}
