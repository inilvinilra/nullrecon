package main

import (
	"strconv"
	"strings"
	"time"

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
	if raw, ok := flagValue(args, "--top-ports"); ok {
		n, err := parsePositiveInt(raw)
		if err != nil {
			return c.fail(exitUsage, "--top-ports must be a positive integer")
		}
		ports = portscan.TopPorts(n)
	}
	if flagPresent(args, "--all-ports") {
		ports = allPorts()
	}
	if len(ports) == 0 {
		return c.fail(exitUsage, "no ports in scope; pass --ports 80,443,1000-2000, --top-ports N, or --all-ports")
	}
	engine := portscan.New(snap, budgetFromScope(snap)).WithBanners(true)
	if len(ports) > 2000 {
		engine.WithConcurrency(1000).WithDialTimeout(1500 * time.Millisecond).WithAttempts(1)
	}
	if raw, ok := flagValue(args, "--concurrency"); ok {
		if n, err := parsePositiveInt(raw); err == nil {
			engine.WithConcurrency(n)
		}
	}
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
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if n > 0 && n <= 65535 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && a <= b {
				for n := a; n <= b; n++ {
					add(n)
				}
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			add(n)
		}
	}
	return out
}

func allPorts() []int {
	out := make([]int, 65535)
	for i := range out {
		out[i] = i + 1
	}
	return out
}
