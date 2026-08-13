package vulnmatch

import (
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/domain/technology"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
)

type Engine struct {
	set *RuleSet
	now func() time.Time
}

func New(set *RuleSet) *Engine {
	return &Engine{set: set, now: func() time.Time { return time.Now().UTC() }}
}

func (e *Engine) Match(projectID string, tech technology.Technology) []vulnerability.Candidate {
	v := parseVersion(tech.Version)
	if !v.ok {
		return nil
	}
	rules := e.set.rulesFor(tech.Product)
	if len(rules) == 0 {
		return nil
	}
	now := e.now()
	var out []vulnerability.Candidate
	for _, r := range rules {
		if !vendorMatches(r.Vendor, tech.Vendor) {
			continue
		}
		if !anyConstraintMatches(r.constraints, v) {
			continue
		}
		c := vulnerability.New(projectID, tech.AssetID, vulnerability.MatchProductVersion, "vulnmatch", now)
		c.TechnologyID = tech.ID
		c.CVE = r.CVE
		c.GHSA = r.GHSA
		c.CPE = r.CPE
		c.VersionEvidence = tech.Version
		c.Prereqs = r.Prereqs
		c.State = vulnerability.CandEnriched
		if r.CVSSScore > 0 || r.CVSSVector != "" {
			c.CVSS = &vulnerability.CVSS{Vector: r.CVSSVector, Score: r.CVSSScore, Severity: r.Severity}
		}
		if r.EPSS > 0 {
			epss := r.EPSS
			c.EPSS = &epss
		}
		c.KEV = r.KEV
		c.KEVDueDate = r.KEVDueDate
		out = append(out, c)
	}
	return out
}

func vendorMatches(ruleVendor, techVendor string) bool {
	if ruleVendor == "" || techVendor == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(ruleVendor), strings.TrimSpace(techVendor))
}

func anyConstraintMatches(constraints []constraint, v version) bool {
	for _, c := range constraints {
		if c.matches(v) {
			return true
		}
	}
	return false
}
