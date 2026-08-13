package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/orchestrator"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/engines/fingerprint"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/platform/objectstore"
	"github.com/nullrecon/nullrecon/platform/secretvault"
	"github.com/nullrecon/nullrecon/providers/registry"
)

func (c commandContext) cmdWorkflow(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "workflow requires a subcommand")
	}
	switch args[0] {
	case "list":
		wf := workflow.Baseline()
		names := []string{}
		for _, n := range wf.Nodes {
			names = append(names, n.Name)
		}
		return c.emit(map[string]any{"workflows": []map[string]any{{"name": wf.Name, "version": wf.Version, "nodes": names}}})
	case "plan":
		return c.workflowPlan(args[1:])
	case "run":
		return c.workflowRun(args[1:])
	}
	return c.fail(exitUsage, "unknown workflow subcommand %q", args[0])
}

func (c commandContext) prepareRun(args []string) (context.Context, *database.DB, scopeguard.Snapshot, string, int) {
	ctx := context.Background()
	slug, okSlug := flagValue(args, "--project")
	label, okLabel := flagValue(args, "--label")
	modeRaw, okMode := flagValue(args, "--mode")
	if !okSlug || !okLabel || !okMode {
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitUsage, "requires --project, --label and --mode")
	}
	mode, err := policy.ParseMode(modeRaw)
	if err != nil {
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitUsage, "%v", err)
	}
	db, err := c.openDB()
	if err != nil {
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitError, "%v", err)
	}
	project, err := db.Projects().BySlug(ctx, slug)
	if err != nil {
		db.Close()
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitError, "%v", err)
	}
	scope, err := db.Scopes().Get(ctx, project.ID, label)
	if err != nil {
		db.Close()
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitError, "%v", err)
	}
	authzs, err := db.Authorizations().ForProject(ctx, project.ID)
	if err != nil {
		db.Close()
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitError, "%v", err)
	}
	now := time.Now().UTC()
	var chosen *identity.Authorization
	for _, a := range authzs {
		if !a.ValidAt(now) {
			continue
		}
		for _, m := range a.AllowedModes {
			if m == string(mode) {
				picked := a
				chosen = &picked
			}
		}
	}
	if chosen == nil {
		db.Close()
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitPolicy, "no valid authorization covers mode %s", mode)
	}
	snap, err := scopeguard.Compile(project, *chosen, scope, mode, now)
	if err != nil {
		db.Close()
		return ctx, nil, scopeguard.Snapshot{}, "", c.fail(exitPolicy, "%v", err)
	}
	return ctx, db, snap, project.ID, -1
}

func budgetFromScope(snap scopeguard.Snapshot) *budgetguard.Guard {
	limits := budgetguard.Budget{}
	if snap.Scope.Rate.RequestsPerSecond > 0 {
		limits[budgetguard.DimRPS] = int64(snap.Scope.Rate.RequestsPerSecond)
	}
	if snap.Scope.Concurrency > 0 {
		limits[budgetguard.DimConcurrency] = int64(snap.Scope.Concurrency)
	}
	if snap.Scope.RequestBudget > 0 {
		limits[budgetguard.DimRequests] = snap.Scope.RequestBudget
	}
	if snap.Scope.ByteBudget > 0 {
		limits[budgetguard.DimBytes] = snap.Scope.ByteBudget
	}
	return budgetguard.New("workflow:baseline", limits, nil)
}

func (c commandContext) workflowPlan(args []string) int {
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	_ = ctx
	wf := workflow.Baseline()
	report, err := workflow.Plan(wf, snap, budgetFromScope(snap))
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(report)
}

func (c commandContext) workflowRun(args []string) int {
	ctx, db, snap, projectID, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()
	reg := buildRegistry()
	vault, err := secretvault.Open(configOf(c).VaultDir)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	raw, err := objectstore.Open(configOf(c).EvidenceDir)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	exec := registry.NewExecutor(reg, vaultResolver{db: db, vault: vault}, raw)
	var fp *fingerprint.Engine
	if data, err := os.ReadFile("rules/fingerprint.json"); err == nil {
		var set fingerprint.RuleSet
		if err := json.Unmarshal(data, &set); err == nil {
			fp, _ = fingerprint.NewEngine(set)
		}
	}
	idemKey, ok := flagValue(args, "--idempotency-key")
	if !ok {
		idemKey = contracts.NewID("idem")
	}
	if existing, err := db.ScanRuns().ByIdempotencyKey(ctx, idemKey); err == nil {
		return c.emit(existing)
	}
	run := scanrun.New(projectID, "baseline", workflow.BaselineVersion, string(snap.Mode), snap.ID, snap.Hash, idemKey)
	engine := workflow.NewEngine(db)
	orch := orchestrator.New(orchestrator.Deps{DB: db, Registry: reg, Executor: exec, Raw: raw, Fingerprints: fp})
	orch.RegisterAll(engine)
	if err := engine.Start(ctx, run); err != nil {
		return c.fail(exitError, "%v", err)
	}
	base := &workflow.NodeContext{DB: db, Snapshot: snap, Budget: budgetFromScope(snap)}
	runErr := engine.Run(ctx, workflow.Baseline(), run.ID, base)
	final, err := db.ScanRuns().Get(ctx, run.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	if runErr != nil {
		c.emit(final)
		return exitError
	}
	return c.emit(final)
}

func (c commandContext) cmdScan(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "scan requires a subcommand")
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	switch args[0] {
	case "status":
		id, ok := flagValue(args, "--run")
		if !ok {
			return c.fail(exitUsage, "scan status requires --run")
		}
		run, err := db.ScanRuns().Get(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		jobs, err := db.Jobs().ForRun(ctx, id)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"run": run, "jobs": jobs})
	case "cancel":
		id, ok := flagValue(args, "--run")
		if !ok {
			return c.fail(exitUsage, "scan cancel requires --run")
		}
		engine := workflow.NewEngine(db)
		if err := engine.Cancel(ctx, id); err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]string{"run": id, "status": string(scanrun.RunCancelling)})
	}
	return c.fail(exitUsage, "unknown scan subcommand %q", args[0])
}

var _ = strings.TrimSpace
var _ = fmt.Sprint
