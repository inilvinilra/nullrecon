package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/exposure"
	"github.com/nullrecon/nullrecon/domain/finding"
)

type Exposures struct {
	db *DB
}

func (d *DB) Exposures() *Exposures {
	return &Exposures{db: d}
}

func (r *Exposures) Put(ctx context.Context, e exposure.Exposure) error {
	if e.ID == "" {
		e.ID = contracts.NewID("exp")
	}
	if e.Version == "" {
		e.Versioned = contracts.NewVersioned("exposure")
	}
	data, err := marshal(e)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO exposures(id, project_id, asset_id, category, data, observed_at) VALUES (?,?,?,?,?,?)",
		e.ID, e.ProjectID, e.AssetID, string(e.Category), data, timeString(e.ObservedAt))
	return err
}

func (r *Exposures) ForProject(ctx context.Context, projectID string) ([]exposure.Exposure, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM exposures WHERE project_id = ? ORDER BY observed_at", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.Exposure
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e exposure.Exposure
		if err := unmarshal(data, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type Findings struct {
	db *DB
}

func (d *DB) Findings() *Findings {
	return &Findings{db: d}
}

func (r *Findings) ByFingerprint(ctx context.Context, projectID, key string) (finding.Finding, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM findings WHERE project_id = ? AND fingerprint_key = ?", projectID, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return finding.Finding{}, false, nil
	}
	if err != nil {
		return finding.Finding{}, false, err
	}
	var f finding.Finding
	if err := unmarshal(data, &f); err != nil {
		return finding.Finding{}, false, err
	}
	return f, true, nil
}

func (r *Findings) Upsert(ctx context.Context, f finding.Finding) error {
	if f.ID == "" {
		f.ID = contracts.NewID("fnd")
	}
	if f.Version == "" {
		f.Versioned = contracts.NewVersioned("finding")
	}
	data, err := marshal(f)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO findings(id, project_id, title, state, severity, fingerprint_key, snapshot_hash, first_seen, last_seen, data) VALUES (?,?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(project_id, fingerprint_key) DO UPDATE SET title=excluded.title, state=excluded.state, severity=excluded.severity, snapshot_hash=excluded.snapshot_hash, last_seen=excluded.last_seen, data=excluded.data",
		f.ID, f.ProjectID, f.Title, string(f.State), string(f.Severity), f.FingerprintKey, f.SnapshotHash, timeString(f.FirstSeen), timeString(f.LastSeen), data)
	return err
}

func (r *Findings) List(ctx context.Context, projectID string) ([]finding.Finding, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM findings WHERE project_id = ? ORDER BY last_seen DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finding.Finding
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var f finding.Finding
		if err := unmarshal(data, &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *Findings) Get(ctx context.Context, id string) (finding.Finding, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM findings WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return finding.Finding{}, errors.New("database: finding not found")
	}
	if err != nil {
		return finding.Finding{}, err
	}
	var f finding.Finding
	if err := unmarshal(data, &f); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}
