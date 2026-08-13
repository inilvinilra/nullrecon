package scanrun

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type RunStatus string

const (
	RunPlanned    RunStatus = "planned"
	RunRunning    RunStatus = "running"
	RunCancelling RunStatus = "cancelling"
	RunCancelled  RunStatus = "cancelled"
	RunCompleted  RunStatus = "completed"
	RunFailed     RunStatus = "failed"
)

type ScanRun struct {
	contracts.Versioned
	ID               string            `json:"id"`
	ProjectID        string            `json:"projectId"`
	Workflow         string            `json:"workflow"`
	WorkflowVersion  string            `json:"workflowVersion"`
	Mode             string            `json:"mode"`
	ScopeSnapshotID  string            `json:"scopeSnapshotId"`
	SnapshotHash     string            `json:"snapshotHash"`
	ToolVersions     map[string]string `json:"toolVersions,omitempty"`
	RuleVersions     map[string]string `json:"ruleVersions,omitempty"`
	ProviderVersions map[string]string `json:"providerVersions,omitempty"`
	BudgetSummary    map[string]int64  `json:"budgetSummary,omitempty"`
	IdempotencyKey   string            `json:"idempotencyKey"`
	Status           RunStatus         `json:"status"`
	StartedAt        time.Time         `json:"startedAt,omitempty"`
	EndedAt          time.Time         `json:"endedAt,omitempty"`
	Outcome          string            `json:"outcome,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
}

func New(projectID, workflow, workflowVersion, mode, snapshotID, snapshotHash, idempotencyKey string) ScanRun {
	return ScanRun{
		Versioned:       contracts.NewVersioned("scanrun"),
		ID:              contracts.NewID("run"),
		ProjectID:       projectID,
		Workflow:        workflow,
		WorkflowVersion: workflowVersion,
		Mode:            mode,
		ScopeSnapshotID: snapshotID,
		SnapshotHash:    snapshotHash,
		IdempotencyKey:  idempotencyKey,
		Status:          RunPlanned,
		CreatedAt:       time.Now().UTC(),
	}
}

type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
	JobSkipped   JobStatus = "skipped"
	JobCancelled JobStatus = "cancelled"
)

type Job struct {
	contracts.Versioned
	ID             string    `json:"id"`
	RunID          string    `json:"runId"`
	Node           string    `json:"node"`
	Status         JobStatus `json:"status"`
	AttemptCount   int       `json:"attemptCount"`
	MaxAttempts    int       `json:"maxAttempts"`
	IdempotencyKey string    `json:"idempotencyKey"`
	Checkpoint     []byte    `json:"checkpoint,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type JobAttempt struct {
	contracts.Versioned
	ID        string    `json:"id"`
	JobID     string    `json:"jobId"`
	Number    int       `json:"number"`
	Status    JobStatus `json:"status"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"startedAt"`
	EndedAt   time.Time `json:"endedAt,omitempty"`
}
