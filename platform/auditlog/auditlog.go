package auditlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/platform/database"
)

type Entry struct {
	contracts.Versioned
	Seq        int64     `json:"seq"`
	ID         string    `json:"id"`
	ProjectID  string    `json:"projectId,omitempty"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	TargetHash string    `json:"targetHash,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	PrevHash   string    `json:"prevHash"`
	Hash       string    `json:"hash"`
	At         time.Time `json:"at"`
	Detail     string    `json:"detail,omitempty"`
}

type Log struct {
	db *database.DB
}

func New(db *database.DB) *Log {
	return &Log{db: db}
}

func (l *Log) Append(ctx context.Context, projectID, actor, action, targetHash, reason, detail string) (Entry, error) {
	var prev string
	err := l.db.QueryRowContext(ctx, "SELECT hash FROM auditentries ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		prev = "genesis"
	} else if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Versioned:  contracts.NewVersioned("auditentry"),
		ID:         contracts.NewID("aud"),
		ProjectID:  projectID,
		Actor:      actor,
		Action:     action,
		TargetHash: targetHash,
		Reason:     reason,
		PrevHash:   prev,
		At:         time.Now().UTC(),
		Detail:     detail,
	}
	hash, err := entryHash(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = hash
	data, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	res, err := l.db.ExecContext(ctx,
		"INSERT INTO auditentries(id, project_id, actor, action, target_hash, reason, prev_hash, hash, at, data) VALUES (?,?,?,?,?,?,?,?,?,?)",
		e.ID, nullable(e.ProjectID), e.Actor, e.Action, nullable(e.TargetHash), nullable(e.Reason), e.PrevHash, e.Hash, e.At.Format(time.RFC3339Nano), string(data))
	if err != nil {
		return Entry{}, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return Entry{}, err
	}
	e.Seq = seq
	return e, nil
}

func entryHash(e Entry) (string, error) {
	type wire struct {
		ID         string `json:"id"`
		ProjectID  string `json:"projectId"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		TargetHash string `json:"targetHash"`
		Reason     string `json:"reason"`
		PrevHash   string `json:"prevHash"`
		At         string `json:"at"`
		Detail     string `json:"detail"`
	}
	return contracts.HashHex(wire{e.ID, e.ProjectID, e.Actor, e.Action, e.TargetHash, e.Reason, e.PrevHash, e.At.Format(time.RFC3339Nano), e.Detail})
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (l *Log) List(ctx context.Context, projectID string) ([]Entry, error) {
	query := "SELECT seq, data FROM auditentries"
	args := []any{}
	if projectID != "" {
		query += " WHERE project_id = ?"
		args = append(args, projectID)
	}
	query += " ORDER BY seq"
	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var seq int64
		var data string
		if err := rows.Scan(&seq, &data); err != nil {
			return nil, err
		}
		var e Entry
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return nil, err
		}
		e.Seq = seq
		out = append(out, e)
	}
	return out, rows.Err()
}

func (l *Log) Verify(ctx context.Context) error {
	entries, err := l.List(ctx, "")
	if err != nil {
		return err
	}
	prev := "genesis"
	for _, e := range entries {
		if e.PrevHash != prev {
			return fmt.Errorf("auditlog: chain broken at seq %d", e.Seq)
		}
		hash, err := entryHash(e)
		if err != nil {
			return err
		}
		if hash != e.Hash {
			return fmt.Errorf("auditlog: hash mismatch at seq %d", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}
