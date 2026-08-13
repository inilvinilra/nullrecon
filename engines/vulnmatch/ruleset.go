package vulnmatch

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nullrecon/nullrecon/contracts"
)

//go:embed rules.json
var embeddedRules []byte

type Rule struct {
	ID          string   `json:"id"`
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor,omitempty"`
	Affected    []string `json:"affected"`
	FixedIn     string   `json:"fixedIn,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	GHSA        string   `json:"ghsa,omitempty"`
	CPE         string   `json:"cpe,omitempty"`
	CVSSVector  string   `json:"cvssVector,omitempty"`
	CVSSScore   float64  `json:"cvssScore,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	EPSS        float64  `json:"epss,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	KEVDueDate  string   `json:"kevDueDate,omitempty"`
	Prereqs     []string `json:"prereqs,omitempty"`
	Description string   `json:"description,omitempty"`

	constraints []constraint
}

type RuleSet struct {
	contracts.Versioned
	Rules   []Rule `json:"rules"`
	byLower map[string][]Rule
}

func LoadRules() (*RuleSet, error) {
	return parseRules(embeddedRules)
}

func parseRules(data []byte) (*RuleSet, error) {
	var set RuleSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("vulnmatch: parse ruleset: %w", err)
	}
	set.Version = contracts.RuleSetV1
	set.Kind = "vulnrules"
	set.byLower = map[string][]Rule{}
	for i := range set.Rules {
		r := &set.Rules[i]
		if r.Product == "" || len(r.Affected) == 0 {
			return nil, fmt.Errorf("vulnmatch: rule %s missing product or affected ranges", r.ID)
		}
		for _, expr := range r.Affected {
			c := parseConstraint(expr)
			if !c.ok {
				return nil, fmt.Errorf("vulnmatch: rule %s has invalid range %q", r.ID, expr)
			}
			r.constraints = append(r.constraints, c)
		}
		key := strings.ToLower(r.Product)
		set.byLower[key] = append(set.byLower[key], *r)
	}
	return &set, nil
}

func (s *RuleSet) rulesFor(product string) []Rule {
	return s.byLower[strings.ToLower(strings.TrimSpace(product))]
}
