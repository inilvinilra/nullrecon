package main

import (
	"context"
	"fmt"
	"time"

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
	case "import":
		return c.cveImport(db, args[1:])
	case "match":
		return c.cveMatch(db, args[1:])
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
			until, _ := flagValue(args, "--until")
			windows, err := cveWindows(since, until)
			if err != nil {
				return c.fail(exitUsage, "%v", err)
			}
			for _, wnd := range windows {
				queries = append(queries, syncQuery{provider: "nvd", query: registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"lastModStartDate": wnd.start, "lastModEndDate": wnd.end}}})
			}
		}
		if pubSince, ok := flagValue(args, "--pub-since"); ok {
			pubUntil, _ := flagValue(args, "--pub-until")
			windows, err := cveWindows(pubSince, pubUntil)
			if err != nil {
				return c.fail(exitUsage, "%v", err)
			}
			for _, wnd := range windows {
				queries = append(queries, syncQuery{provider: "nvd", query: registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"pubStartDate": wnd.start, "pubEndDate": wnd.end}}})
			}
		}
	}
	if len(queries) == 0 {
		return c.fail(exitUsage, "cve sync requires one of --kev, --cve, --keyword, --since, or --pub-since")
	}

	delay := syncDelay(ctx, db)
	ingestor := cvefeed.NewIngestor()
	fetched := 0
	stored := 0
	var failures []string
	for i, sq := range queries {
		records, err := runSync(ctx, exec, sq, delay)
		fetched += len(records)
		for _, rec := range ingestor.Merge(records) {
			if uerr := db.CVEKnowledge().Upsert(ctx, rec); uerr != nil {
				return c.fail(exitError, "%v", uerr)
			}
			stored++
		}
		if err != nil {
			failures = append(failures, err.Error())
		}
		if len(queries) > 1 {
			fmt.Fprintf(c.stderr, "cve sync: window %d/%d done, %d stored so far\n", i+1, len(queries), stored)
		}
	}
	return c.emit(map[string]any{"fetched": fetched, "stored": stored, "windows": len(queries), "failures": failures})
}

func syncDelay(ctx context.Context, db *database.DB) time.Duration {
	if _, err := db.ProviderConfigs().Get(ctx, "nvd"); err == nil {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

type syncQuery struct {
	provider string
	query    registry.Query
}

func runSync(ctx context.Context, exec *registry.Executor, sq syncQuery, delay time.Duration) ([]registry.Record, error) {
	var out []registry.Record
	q := sq.query
	for page := 0; page < maxSyncPages; page++ {
		if page > 0 && delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return out, ctx.Err()
			case <-timer.C:
			}
		}
		res, err := exec.Execute(ctx, sq.provider, q)
		if err != nil {
			return out, err
		}
		out = append(out, res.Records...)
		if res.NextCursor == "" {
			return out, nil
		}
		q.Cursor = res.NextCursor
	}
	return out, nil
}

type cveWindow struct {
	start string
	end   string
}

const nvdTimeLayout = "2006-01-02T15:04:05.000"

func cveWindows(sinceRaw, untilRaw string) ([]cveWindow, error) {
	since, err := time.Parse(nvdTimeLayout, sinceRaw)
	if err != nil {
		return nil, fmt.Errorf("--since must be like 2026-01-02T00:00:00.000: %v", err)
	}
	until := time.Now().UTC()
	if untilRaw != "" {
		until, err = time.Parse(nvdTimeLayout, untilRaw)
		if err != nil {
			return nil, fmt.Errorf("--until must be like 2026-01-02T00:00:00.000: %v", err)
		}
	}
	if !until.After(since) {
		return nil, fmt.Errorf("--until must be after --since")
	}
	const maxWindow = 119 * 24 * time.Hour
	var windows []cveWindow
	for cursor := since; cursor.Before(until); {
		end := cursor.Add(maxWindow)
		if end.After(until) {
			end = until
		}
		windows = append(windows, cveWindow{start: cursor.UTC().Format(nvdTimeLayout), end: end.UTC().Format(nvdTimeLayout)})
		cursor = end
	}
	return windows, nil
}

func flagPresent(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
