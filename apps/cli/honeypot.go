package main

import (
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/honeysense"
	"github.com/nullrecon/nullrecon/engines/portscan"
)

func (c commandContext) cmdHoneypot(args []string) int {
	host, hasHost := positionalOrFlag(args, "--host")
	ip, hasIP := flagValue(args, "--ip")
	if !hasHost && !hasIP {
		return c.fail(exitUsage, "honeypot requires a --host or --ip")
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
		return c.fail(exitUsage, "no ports in scope; pass --ports")
	}
	res, err := portscan.New(snap, budgetFromScope(snap)).WithBanners(true).Scan(ctx, scopeguard.Target{Host: host, IP: ip}, ports)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	signals := honeysense.Signals{Banners: map[int]string{}}
	for _, p := range res.Ports {
		if !p.Open {
			continue
		}
		signals.OpenPorts = append(signals.OpenPorts, p.Port)
		if p.Banner != "" {
			signals.Banners[p.Port] = p.Banner
		}
	}
	verdict := honeysense.Score(signals)
	return c.emit(map[string]any{
		"target":         firstNonEmpty(host, ip),
		"openPorts":      signals.OpenPorts,
		"honeypotScore":  verdict.Score,
		"recommendation": verdict.Recommendation,
		"requiresReview": verdict.RequiresReview,
		"components":     verdict.Components,
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
