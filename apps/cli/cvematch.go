package main

import (
	"context"
	"sort"

	"github.com/nullrecon/nullrecon/domain/technology"
	"github.com/nullrecon/nullrecon/engines/vulnmatch"
	"github.com/nullrecon/nullrecon/platform/database"
)

func (c commandContext) cveMatch(db *database.DB, args []string) int {
	product, ok := flagValue(args, "--product")
	if !ok {
		return c.fail(exitUsage, "cve match requires --product")
	}
	version, ok := flagValue(args, "--version")
	if !ok {
		return c.fail(exitUsage, "cve match requires --version")
	}
	vendor, _ := flagValue(args, "--vendor")
	ctx := context.Background()
	records, err := db.CVEKnowledge().ForProduct(ctx, product)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	tech := technology.Technology{ID: "adhoc", AssetID: "adhoc", Product: product, Version: version, Vendor: vendor}
	candidates := vulnmatch.NewStoreMatcher().Match("adhoc", tech, records)
	type hit struct {
		CVE      string  `json:"cve"`
		Score    float64 `json:"cvss"`
		Severity string  `json:"severity"`
		KEV      bool    `json:"kev"`
	}
	hits := make([]hit, 0, len(candidates))
	for _, cand := range candidates {
		h := hit{CVE: cand.CVE, KEV: cand.KEV}
		if cand.CVSS != nil {
			h.Score = cand.CVSS.Score
			h.Severity = cand.CVSS.Severity
		}
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	return c.emit(map[string]any{
		"product":         product,
		"version":         version,
		"knownForProduct": len(records),
		"matches":         hits,
		"matchCount":      len(hits),
	})
}
