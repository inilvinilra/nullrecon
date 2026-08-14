package main

import (
	"strconv"

	"github.com/nullrecon/nullrecon/engines/svcaudit"
)

func (c commandContext) cmdSvc(args []string) int {
	host, ok := positionalOrFlag(args, "--host")
	if !ok {
		return c.fail(exitUsage, "svc requires a --host")
	}
	portStr, ok := flagValue(args, "--port")
	if !ok {
		return c.fail(exitUsage, "svc requires a --port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return c.fail(exitUsage, "invalid --port")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	engine := svcaudit.New(snap, budgetFromScope(snap))
	res, err := engine.Scan(ctx, host, port)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(res)
}
