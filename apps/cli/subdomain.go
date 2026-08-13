package main

import "github.com/nullrecon/nullrecon/engines/dnsbrute"

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
	engine := dnsbrute.New(snap, budgetFromScope(snap))
	summary, err := engine.Discover(ctx, domain, dnsbrute.Options{})
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(summary)
}
