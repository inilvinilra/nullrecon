package main

import (
	"context"

	"github.com/nullrecon/nullrecon/engines/cvefeed"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/platform/secretvault"
	"github.com/nullrecon/nullrecon/providers/registry"
)

const maxSyncPages = 50

func (c commandContext) cmdCVE(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "cve requires a subcommand (sync, stats, show)")
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	switch args[0] {
	case "stats":
		stats, err := db.CVEKnowledge().Stats(ctx)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(stats)
	case "show":
		id, ok := positionalOrFlag(args[1:], "--cve")
		if !ok {
			return c.fail(exitUsage, "cve show requires a CVE id")
		}
		rec, found, err := db.CVEKnowledge().Get(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		if !found {
			return c.fail(exitError, "cve %s not in local knowledge base", id)
		}
		return c.emit(rec)
	case "sync":
		return c.cveSync(db, args[1:])
	}
	return c.fail(exitUsage, "unknown cve subcommand %q", args[0])
}

func (c commandContext) cveSync(db *database.DB, args []string) int {
	reg := buildRegistry()
	vault, err := secretvault.Open(configOf(c).VaultDir)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	exec := registry.NewExecutor(reg, vaultResolver{db: db, vault: vault}, nil)
	ctx := context.Background()

	var queries []syncQuery
	switch {
	case flagPresent(args, "--kev"):
		queries = append(queries, syncQuery{provider: "cisa-kev", query: registry.Query{Capability: registry.CapExploitPriority}})
	default:
		if cve, ok := flagValue(args, "--cve"); ok {
			queries = append(queries, syncQuery{provider: "nvd", query: registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"cveId": cve}}})
		}
		if kw, ok := flagValue(args, "--keyword"); ok {
			queries = append(queries, syncQuery{provider: "nvd", query: registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"keyword": kw}}})
		}
		if since, ok := flagValue(args, "--since"); ok {
			queries = append(queries, syncQuery{provider: "nvd", query: registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"lastModStartDate": since}}})
		}
	}
	if len(queries) == 0 {
		return c.fail(exitUsage, "cve sync requires one of --kev, --cve, --keyword, or --since")
	}

	var collected []registry.Record
	truncated := false
	for _, sq := range queries {
		records, tr, err := runSync(ctx, exec, sq)
		if err != nil {
			return c.fail(exitError, "%s: %v", sq.provider, err)
		}
		truncated = truncated || tr
		collected = append(collected, records...)
	}

	merged := cvefeed.NewIngestor().Merge(collected)
	stored := 0
	for _, rec := range merged {
		if err := db.CVEKnowledge().Upsert(ctx, rec); err != nil {
			return c.fail(exitError, "%v", err)
		}
		stored++
	}
	return c.emit(map[string]any{"fetched": len(collected), "stored": stored, "truncated": truncated})
}

type syncQuery struct {
	provider string
	query    registry.Query
}

func runSync(ctx context.Context, exec *registry.Executor, sq syncQuery) ([]registry.Record, bool, error) {
	var out []registry.Record
	q := sq.query
	for page := 0; page < maxSyncPages; page++ {
		res, err := exec.Execute(ctx, sq.provider, q)
		if err != nil {
			return nil, false, err
		}
		out = append(out, res.Records...)
		if res.NextCursor == "" {
			return out, false, nil
		}
		q.Cursor = res.NextCursor
	}
	return out, true, nil
}

func flagPresent(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
