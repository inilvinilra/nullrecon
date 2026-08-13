package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/platform/database"
)

func TestBaselineValidates(t *testing.T) {
	wf := Baseline()
	if err := wf.Validate(); err != nil {
		t.Fatal(err)
	}
	order, err := wf.TopoSort()
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 26 {
		t.Fatalf("baseline must have 26 nodes, got %d", len(order))
	}
	seen := map[string]int{}
	for i, n := range order {
		seen[n.Name] = i
	}
	for _, n := range wf.Nodes {
		for _, dep := range n.DependsOn {
			if seen[dep] >= seen[n.Name] {
				t.Fatalf("node %s appears before dependency %s", n.Name, dep)
			}
		}
	}
}

func TestCycleRejected(t *testing.T) {
	wf := Workflow{Name: "bad", Version: "1", Nodes: []Node{
		{Name: "a", MaxAttempts: 1, DependsOn: []string{"b"}},
		{Name: "b", MaxAttempts: 1, DependsOn: []string{"a"}},
	}}
	if err := wf.Validate(); err == nil {
		t.Fatal("cycle must be rejected")
	}
}

func openDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newRun() scanrun.ScanRun {
	return scanrun.New("prj-1", "test", "1.0.0", "passive", "scp-1", "hash", "idem-1")
}

func okHandler(payload string) Handler {
	return func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		return json.RawMessage(`{"value":"` + payload + `"}`), nil, nil
	}
}

func TestEngineRunsDAG(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{
		{Name: "first", MaxAttempts: 1, FailurePolicy: FailAbort},
		{Name: "second", MaxAttempts: 1, DependsOn: []string{"first"}},
	}}
	if err := wf.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Register("first", okHandler("one"))
	e.Register("second", func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		if _, ok := nc.Input["first"]; !ok {
			return nil, nil, errors.New("missing dependency output")
		}
		return json.RawMessage(`{"value":"two"}`), nil, nil
	})
	run := newRun()
	ctx := context.Background()
	if err := e.Start(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db}); err != nil {
		t.Fatal(err)
	}
	got, err := db.ScanRuns().Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != scanrun.RunCompleted {
		t.Fatalf("run must complete, got %s", got.Status)
	}
	jobs, _ := db.Jobs().ForRun(ctx, run.ID)
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Status != scanrun.JobSucceeded {
			t.Fatalf("job %s must succeed, got %s", j.Node, j.Status)
		}
		attempts, _ := db.Jobs().Attempts(ctx, j.ID)
		if len(attempts) != 1 {
			t.Fatalf("job %s must record one attempt", j.Node)
		}
	}
}

func TestEngineResumeSkipsSucceeded(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{
		{Name: "first", MaxAttempts: 1},
		{Name: "second", MaxAttempts: 1, DependsOn: []string{"first"}},
	}}
	var calls int
	e.Register("first", func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		calls++
		return json.RawMessage(`{"value":"one"}`), nil, nil
	})
	e.Register("second", okHandler("two"))
	run := newRun()
	ctx := context.Background()
	e.Start(ctx, run)
	if err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("resumed run must not re-execute succeeded nodes, got %d calls", calls)
	}
}

func TestEngineRetriesThenSucceeds(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{{Name: "flaky", MaxAttempts: 3}}}
	var attempts int
	e.Register("flaky", func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		attempts++
		if attempts < 3 {
			return nil, nil, errors.New("transient")
		}
		return json.RawMessage(`{}`), nil, nil
	})
	run := newRun()
	ctx := context.Background()
	e.Start(ctx, run)
	if err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	jobs, _ := db.Jobs().ForRun(ctx, run.ID)
	recorded, _ := db.Jobs().Attempts(ctx, jobs[0].ID)
	if len(recorded) != 3 {
		t.Fatalf("every attempt must be recorded, got %d", len(recorded))
	}
}

func TestEngineFailureSkipsDependents(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{
		{Name: "bad", MaxAttempts: 1, FailurePolicy: FailSkipDeps},
		{Name: "child", MaxAttempts: 1, DependsOn: []string{"bad"}},
		{Name: "independent", MaxAttempts: 1},
	}}
	e.Register("bad", func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		return nil, nil, errors.New("boom")
	})
	e.Register("child", okHandler("child"))
	e.Register("independent", okHandler("indep"))
	run := newRun()
	ctx := context.Background()
	e.Start(ctx, run)
	err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db})
	if err != nil {
		t.Fatalf("skipdependents failure must not fail the run: %v", err)
	}
	jobs, _ := db.Jobs().ForRun(ctx, run.ID)
	status := map[string]scanrun.JobStatus{}
	for _, j := range jobs {
		status[j.Node] = j.Status
	}
	if status["bad"] != scanrun.JobFailed || status["child"] != scanrun.JobSkipped || status["independent"] != scanrun.JobSucceeded {
		t.Fatalf("bad job states: %+v", status)
	}
}

func TestEngineMissingHandler(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{{Name: "ghost", MaxAttempts: 1}}}
	run := newRun()
	ctx := context.Background()
	e.Start(ctx, run)
	if err := e.Run(ctx, wf, run.ID, &NodeContext{DB: db}); err != nil {
		t.Fatalf("missing handler with default policy must not fail run: %v", err)
	}
	jobs, _ := db.Jobs().ForRun(ctx, run.ID)
	if jobs[0].Status != scanrun.JobFailed {
		t.Fatalf("job must be marked failed, got %s", jobs[0].Status)
	}
}

func TestEngineCancel(t *testing.T) {
	db := openDB(t)
	e := NewEngine(db)
	e.now = time.Now
	wf := Workflow{Name: "test", Version: "1", Nodes: []Node{
		{Name: "first", MaxAttempts: 1},
		{Name: "second", MaxAttempts: 1, DependsOn: []string{"first"}},
	}}
	e.Register("first", func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error) {
		e.Cancel(context.Background(), nc.Run.ID)
		return json.RawMessage(`{}`), nil, nil
	})
	e.Register("second", okHandler("two"))
	run := newRun()
	ctx := context.Background()
	e.Start(ctx, run)
	base := &NodeContext{DB: db, Run: run}
	err := e.Run(ctx, wf, run.ID, base)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPlanDryRun(t *testing.T) {
	wf := Baseline()
	project, authz, scope := scopeFixture(t)
	snap, err := compileSnapshot(project, authz, scope, policy.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Plan(wf, snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.SnapshotHash == "" || len(report.Nodes) != 26 {
		t.Fatalf("bad report: %+v", report)
	}
	for _, n := range report.Nodes {
		if n.Name == "RunContentDiscovery" && n.Allowed {
			t.Fatal("content discovery must not be allowed in passive mode")
		}
		if n.Name == "CollectPassive" && !n.Allowed {
			t.Fatal("passive collection must be allowed in passive mode")
		}
	}
}
