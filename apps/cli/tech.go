package main

import (
	"sort"

	"github.com/nullrecon/nullrecon/engines/fingerprint"
	"github.com/nullrecon/nullrecon/engines/vulnmatch"
	"github.com/nullrecon/nullrecon/engines/webprobe"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

func (c commandContext) cmdTech(args []string) int {
	target, ok := positionalOrFlag(args, "--url")
	if !ok {
		return c.fail(exitUsage, "tech requires a target URL")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	red, err := redaction.New(nil)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	engine, err := fingerprint.DefaultEngine()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	probe := webprobe.New(snap, budgetFromScope(snap), red)
	res, err := probe.Probe(ctx, target)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	features := fingerprint.Features{
		Headers:     res.Headers,
		Cookies:     res.Cookies,
		Title:       res.Title,
		BodySnippet: res.BodySnippet,
		FaviconMMH3: res.FaviconMMH3,
	}
	if res.TLS != nil {
		features.TLSIssuer = res.TLS.IssuerCN
	}
	techs := engine.Apply(features)
	matcher := vulnmatch.NewStoreMatcher()
	type vulnHit struct {
		CVE      string  `json:"cve"`
		Score    float64 `json:"cvss"`
		Severity string  `json:"severity"`
		KEV      bool    `json:"kev"`
	}
	type techOut struct {
		Product    string    `json:"product"`
		Version    string    `json:"version,omitempty"`
		Confidence float64   `json:"confidence"`
		Vulns      []vulnHit `json:"vulns,omitempty"`
		VulnCount  int       `json:"vulnCount"`
	}
	out := make([]techOut, 0, len(techs))
	totalVulns := 0
	for _, tech := range techs {
		t := techOut{Product: tech.Product, Version: tech.Version, Confidence: round2(tech.Confidence)}
		if tech.Version != "" {
			records, ferr := db.CVEKnowledge().ForProduct(ctx, tech.Product)
			if ferr == nil {
				tech.AssetID = "adhoc"
				for _, cand := range matcher.Match("adhoc", tech, records) {
					h := vulnHit{CVE: cand.CVE, KEV: cand.KEV}
					if cand.CVSS != nil {
						h.Score = cand.CVSS.Score
						h.Severity = cand.CVSS.Severity
					}
					t.Vulns = append(t.Vulns, h)
				}
				sort.Slice(t.Vulns, func(i, j int) bool { return t.Vulns[i].Score > t.Vulns[j].Score })
			}
		}
		t.VulnCount = len(t.Vulns)
		totalVulns += t.VulnCount
		out = append(out, t)
	}
	return c.emit(map[string]any{
		"target":       res.FinalURL,
		"status":       res.Status,
		"server":       res.Headers["server"],
		"title":        res.Title,
		"technologies": out,
		"techCount":    len(out),
		"vulnTotal":    totalVulns,
	})
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
