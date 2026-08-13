package main

import "context"

func (c commandContext) cmdFinding(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "finding requires a subcommand")
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	switch args[0] {
	case "list":
		slug, ok := flagValue(args, "--project")
		if !ok {
			return c.fail(exitUsage, "finding list requires --project")
		}
		project, err := db.Projects().BySlug(ctx, slug)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		findings, err := db.Findings().List(ctx, project.ID)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"findings": findings, "count": len(findings)})
	case "show":
		id, ok := positionalOrFlag(args[1:], "--id")
		if !ok {
			return c.fail(exitUsage, "finding show requires a finding id")
		}
		f, err := db.Findings().Get(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(f)
	}
	return c.fail(exitUsage, "unknown finding subcommand %q", args[0])
}

func positionalOrFlag(args []string, flag string) (string, bool) {
	if v, ok := flagValue(args, flag); ok {
		return v, true
	}
	for _, a := range args {
		if len(a) > 0 && a[0] != '-' {
			return a, true
		}
	}
	return "", false
}
