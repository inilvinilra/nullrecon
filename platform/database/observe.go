package database

import (
	"context"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/evidence"
	"github.com/nullrecon/nullrecon/domain/service"
	"github.com/nullrecon/nullrecon/domain/technology"
)

type Observation struct {
	contracts.Versioned
	ID         string `json:"id"`
	ProjectID  string `json:"projectId"`
	AssetID    string `json:"assetId,omitempty"`
	Source     string `json:"source"`
	Kind       string `json:"observationKind"`
	Data       string `json:"data"`
	ObservedAt string `json:"observedAt"`
	FetchedAt  string `json:"fetchedAt"`
	RawHash    string `json:"rawHash,omitempty"`
}

type Observations struct {
	db *DB
}

func (d *DB) Observations() *Observations {
	return &Observations{db: d}
}

func (r *Observations) Append(ctx context.Context, o Observation) error {
	if o.ID == "" {
		o.ID = contracts.NewID("obs")
	}
	if o.Version == "" {
		o.Versioned = contracts.NewVersioned("observation")
	}
	data, err := marshal(o)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO observations(id, project_id, asset_id, source, kind, observed_at, fetched_at, raw_hash, data) VALUES (?,?,?,?,?,?,?,?,?)",
		o.ID, o.ProjectID, o.AssetID, o.Source, o.Kind, o.ObservedAt, o.FetchedAt, o.RawHash, data)
	return err
}

func (r *Observations) ForProject(ctx context.Context, projectID, kind string) ([]Observation, error) {
	query := "SELECT data FROM observations WHERE project_id = ?"
	args := []any{projectID}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, kind)
	}
	query += " ORDER BY observed_at"
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var o Observation
		if err := unmarshal(data, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

type Services struct {
	db *DB
}

func (d *DB) Services() *Services {
	return &Services{db: d}
}

func (r *Services) Upsert(ctx context.Context, s service.Service) error {
	data, err := marshal(s)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO services(id, project_id, asset_id, protocol, port, data, observed_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(asset_id, protocol, port, observed_at) DO NOTHING",
		s.ID, s.ProjectID, s.AssetID, s.Protocol, s.Port, data, timeString(s.ObservedAt))
	return err
}

func (r *Services) ForAsset(ctx context.Context, assetID string) ([]service.Service, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM services WHERE asset_id = ? ORDER BY port, observed_at", assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []service.Service
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var s service.Service
		if err := unmarshal(data, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

type Technologies struct {
	db *DB
}

func (d *DB) Technologies() *Technologies {
	return &Technologies{db: d}
}

func (r *Technologies) Upsert(ctx context.Context, t technology.Technology) error {
	if t.ID == "" {
		t.ID = contracts.NewID("tech")
	}
	if t.Version == "" {
		t.Versioned = contracts.NewVersioned("technology")
	}
	data, err := marshal(t)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO technologies(id, project_id, asset_id, product, version, method, data, observed_at) VALUES (?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(asset_id, product, version, method) DO UPDATE SET data=excluded.data",
		t.ID, t.ProjectID, t.AssetID, t.Product, t.Version, t.Method, data, timeString(t.ObservedAt))
	return err
}

func (r *Technologies) ForAsset(ctx context.Context, assetID string) ([]technology.Technology, error) {
	return r.query(ctx, "SELECT data FROM technologies WHERE asset_id = ? ORDER BY product", assetID)
}

func (r *Technologies) ForProject(ctx context.Context, projectID string) ([]technology.Technology, error) {
	return r.query(ctx, "SELECT data FROM technologies WHERE project_id = ? ORDER BY product", projectID)
}

func (r *Technologies) query(ctx context.Context, sql, arg string) ([]technology.Technology, error) {
	rows, err := r.db.QueryContext(ctx, sql, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []technology.Technology
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var t technology.Technology
		if err := unmarshal(data, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

type EvidenceStore struct {
	db *DB
}

func (d *DB) Evidence() *EvidenceStore {
	return &EvidenceStore{db: d}
}

func (r *EvidenceStore) Put(ctx context.Context, e evidence.Evidence) error {
	if e.ID == "" {
		e.ID = contracts.NewID("evi")
	}
	if e.Version == "" {
		e.Versioned = contracts.NewVersioned("evidence")
	}
	data, err := marshal(e)
	if err != nil {
		return err
	}
	var findingID, runID any
	if e.FindingID != "" {
		findingID = e.FindingID
	}
	if e.RunID != "" {
		runID = e.RunID
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO evidence(id, project_id, finding_id, run_id, kind, storage_ref, captured_at, data) VALUES (?,?,?,?,?,?,?,?)",
		e.ID, e.ProjectID, findingID, runID, string(e.Kind), e.StorageRef, timeString(e.CapturedAt), data)
	return err
}

func (r *EvidenceStore) ForFinding(ctx context.Context, findingID string) ([]evidence.Evidence, error) {
	return r.query(ctx, "SELECT data FROM evidence WHERE finding_id = ? ORDER BY captured_at", findingID)
}

func (r *EvidenceStore) ForRun(ctx context.Context, runID string) ([]evidence.Evidence, error) {
	return r.query(ctx, "SELECT data FROM evidence WHERE run_id = ? ORDER BY captured_at", runID)
}

func (r *EvidenceStore) query(ctx context.Context, sqlQuery string, arg string) ([]evidence.Evidence, error) {
	rows, err := r.db.QueryContext(ctx, sqlQuery, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidence.Evidence
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e evidence.Evidence
		if err := unmarshal(data, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
