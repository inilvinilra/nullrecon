package main

import (
	"github.com/nullrecon/nullrecon/engines/oob"
	"github.com/nullrecon/nullrecon/engines/template"
)

func (c commandContext) cmdTemplate(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "template requires a subcommand (list, scan)")
	}
	switch args[0] {
	case "list":
		return c.templateList()
	case "scan":
		return c.templateScan(args[1:])
	}
	return c.fail(exitUsage, "unknown template subcommand %q", args[0])
}

func (c commandContext) templateList() int {
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

func (c commandContext) templateScan(args []string) int {
	target, ok := positionalOrFlag(args, "--url")
	if !ok {
		return c.fail(exitUsage, "template scan requires a target URL")
	}
	set, err := template.LoadEmbedded()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	engine := template.New(snap, budgetFromScope(snap))
	if flagPresent(args, "--oob") {
		listen, _ := flagValue(args, "--oob-listen")
		interactor, ierr := oob.NewInteractor(listen)
		if ierr != nil {
			return c.fail(exitError, "oob: %v", ierr)
		}
		defer interactor.Close()
		engine.WithInteractor(interactor)
	}
	res, err := engine.Run(ctx, target, set)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	matches := []map[string]any{}
	for _, m := range res.Matches {
		matches = append(matches, map[string]any{"templateId": m.TemplateID, "name": m.Name, "severity": m.Severity, "url": m.URL, "cve": m.CVE})
	}
	return c.emit(map[string]any{"target": res.Target, "requested": res.Requested, "blocked": res.Blocked, "matches": matches, "matchCount": len(matches)})
}
