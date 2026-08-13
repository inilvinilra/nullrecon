package main

import (
	"strconv"
	"strings"

	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/portscan"
)

func (c commandContext) cmdPortscan(args []string) int {
	host, hasHost := positionalOrFlag(args, "--host")
	ip, hasIP := flagValue(args, "--ip")
	if !hasHost && !hasIP {
		return c.fail(exitUsage, "portscan requires a --host or --ip")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	ports := snap.Scope.Ports
	if raw, ok := flagValue(args, "--ports"); ok {
		ports = parsePorts(raw)
	}
	if len(ports) == 0 {
		return c.fail(exitUsage, "no ports in scope; pass --ports 80,443,...")
	}
	engine := portscan.New(snap, budgetFromScope(snap)).WithBanners(true)
	target := scopeguard.Target{Host: host, IP: ip}
	res, err := engine.Scan(ctx, target, ports)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	open := []map[string]any{}
	for _, p := range res.Ports {
		if p.Open {
			open = append(open, map[string]any{"port": p.Port, "banner": p.Banner})
		}
	}
	return c.emit(map[string]any{"target": res.Target, "open": open, "openCount": len(open), "blocked": res.Blocked})
}

func parsePorts(raw string) []int {
	var out []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n > 0 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}
