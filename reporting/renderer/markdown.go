package renderer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nullrecon/nullrecon/domain/finding"
)

func RenderMarkdown(d Data) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	fmt.Fprintf(&b, "- Project: `%s`\n", d.ProjectSlug)
	if d.RunID != "" {
		fmt.Fprintf(&b, "- Run: `%s`\n", d.RunID)
	}
	if d.Mode != "" {
		fmt.Fprintf(&b, "- Mode: `%s`\n", d.Mode)
	}
	if d.SnapshotHash != "" {
		fmt.Fprintf(&b, "- Scope snapshot: `%s`\n", d.SnapshotHash)
	}
	fmt.Fprintf(&b, "- Generated: %s\n\n", d.GeneratedAt.Format("2006-01-02 15:04:05 MST"))

	counts := d.SeverityCounts()
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n| --- | --- |\n")
	for _, sev := range []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo} {
		fmt.Fprintf(&b, "| %s | %d |\n", sev, counts[string(sev)])
	}
	fmt.Fprintf(&b, "| **Total** | **%d** |\n\n", len(d.Findings))
	fmt.Fprintf(&b, "Exposures observed: %d\n\n", d.ExposureCount)
	if len(d.SecretSummary) > 0 {
		b.WriteString("### Secret candidates (fingerprints only)\n\n")
		keys := make([]string, 0, len(d.SecretSummary))
		for k := range d.SecretSummary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- `%s`: %d\n", k, d.SecretSummary[k])
		}
		b.WriteString("\n")
	}

	sorted := make([]finding.Finding, len(d.Findings))
	copy(sorted, d.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if severityOrder(sorted[i].Severity) != severityOrder(sorted[j].Severity) {
			return severityOrder(sorted[i].Severity) < severityOrder(sorted[j].Severity)
		}
		return sorted[i].Title < sorted[j].Title
	})

	b.WriteString("## Findings\n\n")
	if len(sorted) == 0 {
		b.WriteString("No findings.\n")
		return []byte(b.String()), nil
	}
	for _, f := range sorted {
		fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(&b, "- ID: `%s`\n", f.ID)
		fmt.Fprintf(&b, "- State: `%s`\n", f.State)
		fmt.Fprintf(&b, "- Confidence: %.2f\n", f.Confidence.Value)
		if f.WeaknessClass != "" {
			fmt.Fprintf(&b, "- Weakness: `%s`\n", f.WeaknessClass)
		}
		if len(f.AssetIDs) > 0 {
			fmt.Fprintf(&b, "- Assets: %s\n", strings.Join(f.AssetIDs, ", "))
		}
		if f.SnapshotHash != "" {
			fmt.Fprintf(&b, "- Scope snapshot: `%s`\n", f.SnapshotHash)
		}
		fmt.Fprintf(&b, "- First seen: %s\n", f.FirstSeen.Format("2006-01-02"))
		fmt.Fprintf(&b, "- Last seen: %s\n", f.LastSeen.Format("2006-01-02"))
		if f.Summary != "" {
			fmt.Fprintf(&b, "\n%s\n", f.Summary)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "\n**Remediation:** %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}
