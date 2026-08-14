package main

import (
	"sort"

	"github.com/nullrecon/nullrecon/engines/dnsbrute"
	"github.com/nullrecon/nullrecon/engines/subdomain"
	"github.com/nullrecon/nullrecon/platform/secretvault"
	"github.com/nullrecon/nullrecon/providers/registry"
)

func (c commandContext) cmdSubdomain(args []string) int {
	domain, ok := positionalOrFlag(args, "--domain")
	if !ok {
		return c.fail(exitUsage, "subdomain requires a domain (positional or --domain)")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()

	merged := map[string]bool{}
	out := map[string]any{"domain": domain}

	if !flagPresent(args, "--passive-only") {
		engine := dnsbrute.New(snap, budgetFromScope(snap))
		summary, err := engine.Discover(ctx, domain, dnsbrute.Options{})
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		out["active"] = summary
		for _, r := range summary.Results {
			merged[r.Host] = true
		}
	}

	if !flagPresent(args, "--no-passive") {
		reg := buildRegistry()
		vault, err := secretvault.Open(configOf(c).VaultDir)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		exec := registry.NewExecutor(reg, vaultResolver{db: db, vault: vault}, nil)
		sources := subdomain.SubdomainSources(reg)
		passive := subdomain.EnumeratePassive(ctx, exec, sources, domain)
		out["passive"] = passive
		for _, h := range passive.Hostnames {
			merged[h] = true
		}
	}

	hosts := make([]string, 0, len(merged))
	for h := range merged {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out["hostnames"] = hosts
	out["total"] = len(hosts)
	return c.emit(out)
}
