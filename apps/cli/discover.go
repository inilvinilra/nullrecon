package main

import (
	"os"
	"strings"

	"github.com/nullrecon/nullrecon/engines/contentdiscovery"
)

func loadLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func (c commandContext) cmdDiscover(args []string) int {
	target, ok := positionalOrFlag(args, "--url")
	if !ok {
		return c.fail(exitUsage, "discover requires a target URL")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	opts := contentdiscovery.Options{}
	if raw, ok := flagValue(args, "--words-file"); ok {
		words, err := loadLines(raw)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		opts.Words = words
	}
	if raw, ok := flagValue(args, "--ext"); ok {
		for _, e := range strings.Split(raw, ",") {
			if e = strings.TrimSpace(e); e != "" {
				opts.Extensions = append(opts.Extensions, e)
			}
		}
	}
	engine := contentdiscovery.New(snap, budgetFromScope(snap))
	res, err := engine.Scan(ctx, target, opts)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	candidates := []map[string]any{}
	redirects := []map[string]any{}
	byClass := map[string]int{}
	for _, h := range res.Hits {
		byClass[h.Class]++
		switch h.Class {
		case "candidate":
			candidates = append(candidates, map[string]any{"path": h.Path, "status": h.Status, "length": h.Length})
		case "redirect":
			redirects = append(redirects, map[string]any{"path": h.Path, "status": h.Status, "target": h.Redirect})
		}
	}
	return c.emit(map[string]any{
		"target":         res.Target,
		"requested":      res.Requested,
		"blocked":        res.Blocked,
		"catchAll":       res.Baseline.CatchAll,
		"byClass":        byClass,
		"candidates":     candidates,
		"candidateCount": len(candidates),
		"redirects":      redirects,
	})
}
