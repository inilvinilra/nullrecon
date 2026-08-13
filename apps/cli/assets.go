package main

import (
	"context"

	"github.com/nullrecon/nullrecon/domain/asset"
)

func (c commandContext) cmdAsset(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "asset requires a subcommand")
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
			return c.fail(exitUsage, "asset list requires --project")
		}
		project, err := db.Projects().BySlug(ctx, slug)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		var kind asset.Kind
		if v, ok := flagValue(args, "--kind"); ok {
			kind = asset.Kind(v)
		}
		assets, err := db.Assets().List(ctx, project.ID, kind)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(assets)
	case "show":
		id, ok := flagValue(args, "--id")
		if !ok {
			return c.fail(exitUsage, "asset show requires --id")
		}
		a, err := db.Assets().Get(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		claims, err := db.Assets().Claims(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"asset": a, "claims": claims})
	case "graph":
		id, ok := flagValue(args, "--id")
		if !ok {
			return c.fail(exitUsage, "asset graph requires --id")
		}
		if _, err := db.Assets().Get(ctx, id); err != nil {
			return c.fail(exitError, "%v", err)
		}
		rels, err := db.Assets().Relations(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		type edge struct {
			From string `json:"from"`
			To   string `json:"to"`
			Kind string `json:"kind"`
		}
		var edges []edge
		seen := map[string]bool{}
		for _, rel := range rels {
			for _, aid := range []string{rel.FromAssetID, rel.ToAssetID} {
				if seen[aid] || aid == id {
					continue
				}
				seen[aid] = true
			}
			edges = append(edges, edge{From: rel.FromAssetID, To: rel.ToAssetID, Kind: string(rel.Kind)})
		}
		return c.emit(map[string]any{"root": id, "edges": edges})
	}
	return c.fail(exitUsage, "unknown asset subcommand %q", args[0])
}
