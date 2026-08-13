package main

import "github.com/nullrecon/nullrecon/engines/template"

func (c commandContext) cmdTemplate(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return c.fail(exitUsage, "template requires the list subcommand")
	}
	set, err := template.LoadEmbedded()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	type entry struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags,omitempty"`
		CVE      string   `json:"cve,omitempty"`
	}
	var entries []entry
	bySeverity := map[string]int{}
	for _, t := range set.Templates {
		entries = append(entries, entry{ID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity, Tags: t.Info.Tags, CVE: t.Info.CVE})
		bySeverity[t.Info.Severity]++
	}
	return c.emit(map[string]any{"templates": entries, "count": len(entries), "bySeverity": bySeverity})
}
