package main

import (
	"strings"

	"github.com/nullrecon/nullrecon/engines/exposure"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

func (c commandContext) cmdExposure(args []string) int {
	targets := flagValuesAll(args, "--url")
	for _, domain := range flagValuesAll(args, "--domain") {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		targets = append(targets, "https://"+domain)
	}
	if len(targets) == 0 {
		return c.fail(exitUsage, "exposure requires at least one --url or --domain")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	set, err := exposure.LoadSignatures()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	red, err := redaction.New(nil)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	engine := exposure.New(snap, budgetFromScope(snap), red, set)
	results := make([]exposure.Result, 0, len(targets))
	for _, target := range targets {
		res, err := engine.Scan(ctx, target)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		results = append(results, res)
	}
	return c.emit(map[string]any{"results": results})
}
