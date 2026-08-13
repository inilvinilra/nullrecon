package main

import "context"

func (c commandContext) cmdVuln(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return c.fail(exitUsage, "vuln requires the list subcommand")
	}
	slug, ok := flagValue(args, "--project")
	if !ok {
		return c.fail(exitUsage, "vuln list requires --project")
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
	candidates, err := db.VulnCandidates().ForProject(ctx, project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	kev := 0
	for _, cand := range candidates {
		if cand.KEV {
			kev++
		}
	}
	return c.emit(map[string]any{"candidates": candidates, "count": len(candidates), "kev": kev})
}
