package vulnmatch

import (
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/domain/cve"
	"github.com/nullrecon/nullrecon/domain/technology"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
)

type StoreMatcher struct {
	now func() time.Time
}

func NewStoreMatcher() *StoreMatcher {
	return &StoreMatcher{now: func() time.Time { return time.Now().UTC() }}
}

func (m *StoreMatcher) Match(projectID string, tech technology.Technology, records []cve.Record) []vulnerability.Candidate {
	v := parseVersion(normalizeVersion(tech.Product, tech.Version))
	if !v.ok {
		return nil
	}
	now := m.now()
	var out []vulnerability.Candidate
	for _, rec := range records {
		if !affectsVersion(rec.Products, tech, v) {
			continue
		}
		c := vulnerability.New(projectID, tech.AssetID, vulnerability.MatchCPE, "cvestore", now)
		c.TechnologyID = tech.ID
		c.CVE = rec.CVE
		c.VersionEvidence = tech.Version
		c.State = vulnerability.CandEnriched
		if rec.CVSSScore > 0 || rec.CVSSVector != "" {
			c.CVSS = &vulnerability.CVSS{Vector: rec.CVSSVector, Score: rec.CVSSScore, Severity: rec.Severity}
		}
		if rec.EPSS > 0 {
			epss := rec.EPSS
			c.EPSS = &epss
		}
		c.KEV = rec.KEV
		c.KEVDueDate = rec.KEVDueDate
		out = append(out, c)
	}
	return out
}

func affectsVersion(products []cve.Affected, tech technology.Technology, v version) bool {
	product := strings.ToLower(strings.TrimSpace(tech.Product))
	for _, p := range products {
		if strings.ToLower(p.Product) != product {
			continue
		}
		if !vendorMatches(p.Vendor, tech.Vendor) {
			continue
		}
		if constraintFromAffected(p).matches(v) {
			return true
		}
	}
	return false
}

func constraintFromAffected(a cve.Affected) constraint {
	var parts []string
	if a.ExactVersion != "" {
		parts = append(parts, "="+a.ExactVersion)
	}
	if a.RangeStartIncl != "" {
		parts = append(parts, ">="+a.RangeStartIncl)
	}
	if a.RangeStartExcl != "" {
		parts = append(parts, ">"+a.RangeStartExcl)
	}
	if a.RangeEndIncl != "" {
		parts = append(parts, "<="+a.RangeEndIncl)
	}
	if a.RangeEndExcl != "" {
		parts = append(parts, "<"+a.RangeEndExcl)
	}
	if len(parts) == 0 {
		return constraint{}
	}
	return parseConstraint(strings.Join(parts, " "))
}
