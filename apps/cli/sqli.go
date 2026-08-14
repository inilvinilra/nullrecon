package main

import "github.com/nullrecon/nullrecon/engines/sqli"

func (c commandContext) cmdSqli(args []string) int {
	target, ok := positionalOrFlag(args, "--url")
	if !ok {
		return c.fail(exitUsage, "sqli requires a target URL with parameters")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	engine := sqli.New(snap, budgetFromScope(snap))
	if flagPresent(args, "--confirm") {
		engine.WithTimeConfirm()
	}
	res, err := engine.Scan(ctx, target)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(res)
}
