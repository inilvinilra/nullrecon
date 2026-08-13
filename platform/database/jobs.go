package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nullrecon/nullrecon/domain/scanrun"
)

type ScanRuns struct {
	db *DB
}

func (d *DB) ScanRuns() *ScanRuns {
	return &ScanRuns{db: d}
}

func (r *ScanRuns) Put(ctx context.Context, run scanrun.ScanRun) error {
	data, err := marshal(run)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO scanruns(id, project_id, workflow, status, snapshot_hash, idempotency_key, data, created_at) VALUES (?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(idempotency_key) DO NOTHING",
		run.ID, run.ProjectID, run.Workflow, string(run.Status), run.SnapshotHash, run.IdempotencyKey, data, timeString(run.CreatedAt))
	return err
}

func (r *ScanRuns) Update(ctx context.Context, run scanrun.ScanRun) error {
	data, err := marshal(run)
	if err != nil {
		return err
	}
	var started, ended any
	if !run.StartedAt.IsZero() {
		started = timeString(run.StartedAt)
	}
	if !run.EndedAt.IsZero() {
		ended = timeString(run.EndedAt)
	}
	_, err = r.db.ExecContext(ctx,
		"UPDATE scanruns SET status=?, data=?, started_at=?, ended_at=? WHERE id=?",
		string(run.Status), data, started, ended, run.ID)
	return err
}

func (r *ScanRuns) Get(ctx context.Context, id string) (scanrun.ScanRun, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM scanruns WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return scanrun.ScanRun{}, ErrNotFound
	}
	if err != nil {
		return scanrun.ScanRun{}, err
	}
	var run scanrun.ScanRun
	if err := unmarshal(data, &run); err != nil {
		return scanrun.ScanRun{}, err
	}
	run.ID = id
	return run, nil
}

func (r *ScanRuns) ByIdempotencyKey(ctx context.Context, key string) (scanrun.ScanRun, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM scanruns WHERE idempotency_key = ?", key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return scanrun.ScanRun{}, ErrNotFound
	}
	if err != nil {
		return scanrun.ScanRun{}, err
	}
	var run scanrun.ScanRun
	return run, unmarshal(data, &run)
}

func (r *ScanRuns) List(ctx context.Context, projectID string) ([]scanrun.ScanRun, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM scanruns WHERE project_id = ? ORDER BY created_at DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scanrun.ScanRun
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var run scanrun.ScanRun
		if err := unmarshal(data, &run); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

type Jobs struct {
	db *DB
}

func (d *DB) Jobs() *Jobs {
	return &Jobs{db: d}
}

func (r *Jobs) Put(ctx context.Context, j scanrun.Job) error {
	data, err := marshal(j)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO jobs(id, run_id, node, status, idempotency_key, checkpoint, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(run_id, node) DO NOTHING",
		j.ID, j.RunID, j.Node, string(j.Status), j.IdempotencyKey, j.Checkpoint, data, timeString(j.CreatedAt), timeString(j.UpdatedAt))
	return err
}

func (r *Jobs) Update(ctx context.Context, j scanrun.Job) error {
	data, err := marshal(j)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"UPDATE jobs SET status=?, checkpoint=?, data=?, updated_at=? WHERE run_id=? AND node=?",
		string(j.Status), j.Checkpoint, data, timeString(j.UpdatedAt), j.RunID, j.Node)
	return err
}

func (r *Jobs) ForRun(ctx context.Context, runID string) ([]scanrun.Job, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data, checkpoint FROM jobs WHERE run_id = ? ORDER BY created_at", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scanrun.Job
	for rows.Next() {
		var data string
		var checkpoint []byte
		if err := rows.Scan(&data, &checkpoint); err != nil {
			return nil, err
		}
		var j scanrun.Job
		if err := unmarshal(data, &j); err != nil {
			return nil, err
		}
		j.Checkpoint = checkpoint
		out = append(out, j)
	}
	return out, rows.Err()
}

func (r *Jobs) RecordAttempt(ctx context.Context, a scanrun.JobAttempt) error {
	var ended any
	if !a.EndedAt.IsZero() {
		ended = timeString(a.EndedAt)
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO jobattempts(id, job_id, number, status, error, started_at, ended_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(job_id, number) DO NOTHING",
		a.ID, a.JobID, a.Number, string(a.Status), nullableStr(a.Error), timeString(a.StartedAt), ended)
	return err
}

func nullableStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (r *Jobs) Attempts(ctx context.Context, jobID string) ([]scanrun.JobAttempt, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, number, status, COALESCE(error,''), started_at, COALESCE(ended_at,'') FROM jobattempts WHERE job_id = ? ORDER BY number", jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scanrun.JobAttempt
	for rows.Next() {
		var a scanrun.JobAttempt
		var started, ended string
		if err := rows.Scan(&a.ID, &a.Number, &a.Status, &a.Error, &started, &ended); err != nil {
			return nil, err
		}
		a.StartedAt, _ = parseTime(started)
		if ended != "" {
			a.EndedAt, _ = parseTime(ended)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
