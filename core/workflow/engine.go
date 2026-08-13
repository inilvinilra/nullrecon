package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/platform/database"
)

type NodeContext struct {
	DB         *database.DB
	Snapshot   scopeguard.Snapshot
	Run        scanrun.ScanRun
	Input      map[string]json.RawMessage
	Checkpoint []byte
	Budget     *budgetguard.Guard
}

type Handler func(ctx context.Context, nc *NodeContext) (json.RawMessage, []byte, error)

var ErrNoHandler = errors.New("workflow: no handler registered for node")
var ErrCancelled = errors.New("workflow: run cancelled")

type Engine struct {
	db       *database.DB
	handlers map[string]Handler
	now      func() time.Time
}

func NewEngine(db *database.DB) *Engine {
	return &Engine{db: db, handlers: map[string]Handler{}, now: time.Now}
}

func (e *Engine) Register(node string, h Handler) {
	e.handlers[node] = h
}

func (e *Engine) Start(ctx context.Context, run scanrun.ScanRun) error {
	if err := e.db.ScanRuns().Put(ctx, run); err != nil {
		return err
	}
	return nil
}

func (e *Engine) Run(ctx context.Context, wf Workflow, runID string, base *NodeContext) error {
	order, err := wf.TopoSort()
	if err != nil {
		return err
	}
	if err := e.setRunStatus(ctx, runID, scanrun.RunRunning); err != nil {
		return err
	}
	run, err := e.db.ScanRuns().Get(ctx, runID)
	if err != nil {
		return err
	}
	base.Run = run
	outputs := map[string]json.RawMessage{}
	failed := map[string]bool{}
	skipped := map[string]bool{}
	for _, node := range order {
		if err := ctx.Err(); err != nil {
			e.setRunStatus(ctx, runID, scanrun.RunCancelled)
			return ErrCancelled
		}
		if cancel, err := e.runCancelling(ctx, runID); err != nil {
			return err
		} else if cancel {
			e.setRunStatus(ctx, runID, scanrun.RunCancelled)
			return ErrCancelled
		}
		blocked := false
		for _, dep := range node.DependsOn {
			if failed[dep] && node.FailurePolicy == FailAbort {
				return e.failRun(ctx, runID, fmt.Sprintf("dependency %s failed", dep))
			}
			if failed[dep] || skipped[dep] {
				blocked = true
			}
		}
		if blocked {
			skipped[node.Name] = true
			e.recordSkipped(ctx, runID, node)
			continue
		}
		input := map[string]json.RawMessage{}
		for _, dep := range node.DependsOn {
			if out, ok := outputs[dep]; ok {
				input[dep] = out
			}
		}
		out, err := e.runNode(ctx, wf, runID, node, base, input)
		if err != nil {
			if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) {
				e.setRunStatus(ctx, runID, scanrun.RunCancelled)
				return ErrCancelled
			}
			failed[node.Name] = true
			if node.FailurePolicy == FailAbort {
				return e.failRun(ctx, runID, fmt.Sprintf("node %s: %v", node.Name, err))
			}
			continue
		}
		if out != nil {
			outputs[node.Name] = out
		}
	}
	return e.setRunStatus(ctx, runID, scanrun.RunCompleted)
}

func (e *Engine) runNode(ctx context.Context, wf Workflow, runID string, node Node, base *NodeContext, input map[string]json.RawMessage) (json.RawMessage, error) {
	handler, handlerOK := e.handlers[node.Name]
	existing, err := e.jobFor(ctx, runID, node.Name)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status == scanrun.JobSucceeded {
		return outputOf(existing.Checkpoint), nil
	}
	job := scanrun.Job{
		Versioned:      contracts.NewVersioned("job"),
		ID:             contracts.NewID("job"),
		RunID:          runID,
		Node:           node.Name,
		Status:         scanrun.JobPending,
		MaxAttempts:    node.MaxAttempts,
		IdempotencyKey: runID + ":" + node.Name,
		CreatedAt:      e.now().UTC(),
		UpdatedAt:      e.now().UTC(),
	}
	if existing != nil {
		job = *existing
	}
	if existing == nil {
		if err := e.db.Jobs().Put(ctx, job); err != nil {
			return nil, err
		}
	}
	if !handlerOK {
		job.Status = scanrun.JobFailed
		job.UpdatedAt = e.now().UTC()
		e.db.Jobs().Update(ctx, job)
		return nil, fmt.Errorf("%w: %s", ErrNoHandler, node.Name)
	}
	if base != nil && base.Budget != nil && (node.EstRequests > 0 || node.EstCredits > 0) {
		if err := base.Budget.Acquire(ctx, budgetguard.Cost{Requests: node.EstRequests, Credits: node.EstCredits}); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for attempt := 1; attempt <= node.MaxAttempts; attempt++ {
		job.AttemptCount = attempt
		job.Status = scanrun.JobRunning
		job.UpdatedAt = e.now().UTC()
		e.db.Jobs().Update(ctx, job)
		attemptRec := scanrun.JobAttempt{
			Versioned: contracts.NewVersioned("jobattempt"),
			ID:        contracts.NewID("att"),
			JobID:     job.ID,
			Number:    attempt,
			Status:    scanrun.JobRunning,
			StartedAt: e.now().UTC(),
		}
		nodeCtx := *base
		nodeCtx.Input = input
		nodeCtx.Checkpoint = job.Checkpoint
		nodeTimeout := time.Duration(node.TimeoutSeconds) * time.Second
		nodeCtxWithTimeout, cancel := context.WithTimeout(ctx, nodeTimeout)
		out, checkpoint, err := handler(nodeCtxWithTimeout, &nodeCtx)
		cancel()
		attemptRec.EndedAt = e.now().UTC()
		if err != nil {
			attemptRec.Status = scanrun.JobFailed
			attemptRec.Error = sanitizeError(err)
			e.db.Jobs().RecordAttempt(ctx, attemptRec)
			lastErr = err
			if errors.Is(err, context.Canceled) {
				job.Status = scanrun.JobCancelled
				job.UpdatedAt = e.now().UTC()
				e.db.Jobs().Update(ctx, job)
				return nil, err
			}
			continue
		}
		attemptRec.Status = scanrun.JobSucceeded
		e.db.Jobs().RecordAttempt(ctx, attemptRec)
		job.Status = scanrun.JobSucceeded
		job.Checkpoint = checkpointOf(out, checkpoint)
		job.UpdatedAt = e.now().UTC()
		e.db.Jobs().Update(ctx, job)
		return out, nil
	}
	job.Status = scanrun.JobFailed
	job.UpdatedAt = e.now().UTC()
	e.db.Jobs().Update(ctx, job)
	return nil, lastErr
}

func outputOf(checkpoint []byte) json.RawMessage {
	if len(checkpoint) == 0 {
		return nil
	}
	var env checkpointEnvelope
	if err := json.Unmarshal(checkpoint, &env); err != nil {
		return nil
	}
	return env.Output
}

func checkpointOf(out json.RawMessage, checkpoint []byte) []byte {
	env := checkpointEnvelope{Output: out, Checkpoint: checkpoint}
	data, _ := json.Marshal(env)
	return data
}

type checkpointEnvelope struct {
	Output     json.RawMessage `json:"output,omitempty"`
	Checkpoint []byte          `json:"checkpoint,omitempty"`
}

func sanitizeError(err error) string {
	msg := err.Error()
	if len(msg) > 512 {
		return msg[:512]
	}
	return msg
}

func (e *Engine) jobFor(ctx context.Context, runID, node string) (*scanrun.Job, error) {
	jobs, err := e.db.Jobs().ForRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if j.Node == node {
			return &j, nil
		}
	}
	return nil, nil
}

func (e *Engine) setRunStatus(ctx context.Context, runID string, status scanrun.RunStatus) error {
	run, err := e.db.ScanRuns().Get(ctx, runID)
	if err != nil {
		return err
	}
	run.Status = status
	now := e.now().UTC()
	if status == scanrun.RunRunning && run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	if status == scanrun.RunCompleted || status == scanrun.RunFailed || status == scanrun.RunCancelled {
		run.EndedAt = now
	}
	return e.db.ScanRuns().Update(ctx, run)
}

func (e *Engine) runCancelling(ctx context.Context, runID string) (bool, error) {
	run, err := e.db.ScanRuns().Get(ctx, runID)
	if err != nil {
		return false, err
	}
	return run.Status == scanrun.RunCancelling, nil
}

func (e *Engine) failRun(ctx context.Context, runID, reason string) error {
	run, err := e.db.ScanRuns().Get(ctx, runID)
	if err != nil {
		return err
	}
	run.Status = scanrun.RunFailed
	run.Outcome = reason
	run.EndedAt = e.now().UTC()
	e.db.ScanRuns().Update(ctx, run)
	return fmt.Errorf("%s", reason)
}

func (e *Engine) recordSkipped(ctx context.Context, runID string, node Node) {
	job := scanrun.Job{
		Versioned:      contracts.NewVersioned("job"),
		ID:             contracts.NewID("job"),
		RunID:          runID,
		Node:           node.Name,
		Status:         scanrun.JobSkipped,
		IdempotencyKey: runID + ":" + node.Name,
		CreatedAt:      e.now().UTC(),
		UpdatedAt:      e.now().UTC(),
	}
	e.db.Jobs().Put(ctx, job)
}

func (e *Engine) Cancel(ctx context.Context, runID string) error {
	run, err := e.db.ScanRuns().Get(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status == scanrun.RunCompleted || run.Status == scanrun.RunFailed || run.Status == scanrun.RunCancelled {
		return nil
	}
	run.Status = scanrun.RunCancelling
	return e.db.ScanRuns().Update(ctx, run)
}
