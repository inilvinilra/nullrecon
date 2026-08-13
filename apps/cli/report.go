package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nullrecon/nullrecon/reporting/renderer"
)

func (c commandContext) cmdReport(args []string) int {
	if len(args) == 0 || args[0] != "build" {
		return c.fail(exitUsage, "report requires the build subcommand")
	}
	slug, ok := flagValue(args, "--project")
	if !ok {
		return c.fail(exitUsage, "report build requires --project")
	}
	format, ok := flagValue(args, "--format")
	if !ok {
		format = "markdown"
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	project, err := db.Projects().BySlug(ctx, slug)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	findings, err := db.Findings().List(ctx, project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	exposures, err := db.Exposures().ForProject(ctx, project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	secrets, err := db.SecretCandidates().ForProject(ctx, project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	vulns, err := db.VulnCandidates().ForProject(ctx, project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	data := renderer.New(project.ID, project.Slug, time.Now())
	data.Findings = findings
	data.ExposureCount = len(exposures)
	data.VulnerabilityCount = len(vulns)
	for _, v := range vulns {
		if v.KEV {
			data.KEVCount++
		}
	}
	summary := map[string]int{}
	for _, s := range secrets {
		summary[s.Detector]++
	}
	data.SecretSummary = summary
	if run, ok := flagValue(args, "--run"); ok {
		data.RunID = run
	}
	var rendered []byte
	switch format {
	case "json":
		rendered, err = renderer.RenderJSON(data)
	case "markdown", "md":
		rendered, err = renderer.RenderMarkdown(data)
	case "sarif":
		rendered, err = renderer.RenderSARIF(data)
	default:
		return c.fail(exitUsage, "unknown report format %q (json, markdown, sarif)", format)
	}
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	if file, ok := flagValue(args, "--out"); ok {
		if err := os.WriteFile(file, rendered, 0o600); err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"status": "written", "path": file, "bytes": len(rendered), "findings": len(findings)})
	}
	fmt.Fprintln(c.stdout, string(rendered))
	return exitOK
}
