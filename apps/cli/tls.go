package main

import "github.com/nullrecon/nullrecon/engines/tlsscan"

func (c commandContext) cmdTLS(args []string) int {
	target, ok := positionalOrFlag(args, "--host")
	if !ok {
		return c.fail(exitUsage, "tls requires a host (positional or --host), e.g. example.com:443")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	engine := tlsscan.New(snap, budgetFromScope(snap))
	res, err := engine.Scan(ctx, target)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(res)
}
