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
	versions := candidateVersions(tech.Product, tech.Version)
	if len(versions) == 0 {
		return nil
	}
	now := m.now()
	var out []vulnerability.Candidate
	for _, rec := range records {
		if !affectsVersion(rec.Products, tech, versions) {
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

func candidateVersions(product, raw string) []version {
	var out []version
	if v := parseVersion(raw); v.ok {
		out = append(out, v)
	}
	if norm := normalizeVersion(product, raw); norm != raw {
		if v := parseVersion(norm); v.ok {
			out = append(out, v)
		}
	}
	return out
}

func affectsVersion(products []cve.Affected, tech technology.Technology, versions []version) bool {
	product := strings.ToLower(strings.TrimSpace(tech.Product))
	for _, p := range products {
		if strings.ToLower(p.Product) != product {
			continue
		}
		if !vendorMatches(p.Vendor, tech.Vendor) {
			continue
		}
		c := constraintFromAffected(p)
		for _, v := range versions {
			if c.matches(v) {
				return true
			}
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
