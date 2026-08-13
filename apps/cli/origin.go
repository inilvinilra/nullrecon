package main

import (
	"context"
	"net"
	"strings"

	"github.com/nullrecon/nullrecon/engines/originip"
)

func (c commandContext) cmdOrigin(args []string) int {
	domain, ok := flagValue(args, "--domain")
	if !ok {
		return c.fail(exitUsage, "origin requires --domain")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	nm, err := originip.LoadNetworkMap()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	ips := resolveCandidateIPs(ctx, domain, flagValuesAll(args, "--host"), flagValuesAll(args, "--ip"))
	engine := originip.New(snap, budgetFromScope(snap), nm)
	res, err := engine.Scan(ctx, domain, ips)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(res)
}

func resolveCandidateIPs(ctx context.Context, domain string, hosts, extra []string) []string {
	set := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip == "" || set[ip] {
			return
		}
		set[ip] = true
		out = append(out, ip)
	}
	names := append([]string{domain}, hosts...)
	resolver := net.DefaultResolver
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		addrs, err := resolver.LookupIPAddr(ctx, name)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			add(a.IP.String())
		}
	}
	for _, ip := range extra {
		add(strings.TrimSpace(ip))
	}
	return out
}

func flagValuesAll(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			out = append(out, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(args[i], name+"=") {
			out = append(out, strings.TrimPrefix(args[i], name+"="))
		}
	}
	return out
}
