package main

import "github.com/nullrecon/nullrecon/engines/dnsaudit"

func (c commandContext) cmdDNS(args []string) int {
	domain, ok := positionalOrFlag(args, "--domain")
	if !ok {
		return c.fail(exitUsage, "dns requires a domain (positional or --domain)")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	engine := dnsaudit.New(snap, budgetFromScope(snap))
	res, err := engine.Scan(ctx, domain)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(res)
}
