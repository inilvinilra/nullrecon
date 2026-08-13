package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

var ErrNotFound = errors.New("database: record not found")

func marshal(v any) (string, error) {
	data, err := json.Marshal(v)
	return string(data), err
}

func unmarshal(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}

func timeString(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

type Projects struct {
	db *DB
}

func (d *DB) Projects() *Projects {
	return &Projects{db: d}
}

func (r *Projects) Put(ctx context.Context, p identity.Project) error {
	data, err := marshal(p)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO projects(id, slug, name, status, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(id) DO UPDATE SET name=excluded.name, status=excluded.status, data=excluded.data, updated_at=excluded.updated_at",
		p.ID, p.Slug, p.Name, string(p.Status), data, timeString(p.CreatedAt), timeString(p.UpdatedAt))
	return err
}

func (r *Projects) Get(ctx context.Context, id string) (identity.Project, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM projects WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.Project{}, ErrNotFound
	}
	if err != nil {
		return identity.Project{}, err
	}
	var p identity.Project
	return p, unmarshal(data, &p)
}

func (r *Projects) BySlug(ctx context.Context, slug string) (identity.Project, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM projects WHERE slug = ?", slug).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.Project{}, ErrNotFound
	}
	if err != nil {
		return identity.Project{}, err
	}
	var p identity.Project
	return p, unmarshal(data, &p)
}

func (r *Projects) List(ctx context.Context) ([]identity.Project, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM projects ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Project
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var p identity.Project
		if err := unmarshal(data, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type Authorizations struct {
	db *DB
}

func (d *DB) Authorizations() *Authorizations {
	return &Authorizations{db: d}
}

func (r *Authorizations) Put(ctx context.Context, a identity.Authorization) error {
	data, err := marshal(a)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO authorizations(id, project_id, valid_from, valid_to, data, created_at) VALUES (?,?,?,?,?,?) "+
			"ON CONFLICT(id) DO UPDATE SET data=excluded.data, valid_from=excluded.valid_from, valid_to=excluded.valid_to",
		a.ID, a.ProjectID, timeString(a.ValidFrom), timeString(a.ValidTo), data, timeString(a.CreatedAt))
	return err
}

func (r *Authorizations) ForProject(ctx context.Context, projectID string) ([]identity.Authorization, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM authorizations WHERE project_id = ? ORDER BY created_at", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Authorization
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var a identity.Authorization
		if err := unmarshal(data, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type Scopes struct {
	db *DB
}

func (d *DB) Scopes() *Scopes {
	return &Scopes{db: d}
}

func (r *Scopes) Put(ctx context.Context, projectID, label string, scope scopeguard.Scope) (string, error) {
	data, err := marshal(scope)
	if err != nil {
		return "", err
	}
	id, err := scopeID(projectID, label)
	if err != nil {
		return "", err
	}
	now := timeString(time.Now())
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO scopes(id, project_id, label, data, created_at) VALUES (?,?,?,?,?) "+
			"ON CONFLICT(project_id, label) DO UPDATE SET data=excluded.data",
		id, projectID, label, data, now)
	return id, err
}

func scopeID(projectID, label string) (string, error) {
	sum := struct {
		P string `json:"p"`
		L string `json:"l"`
	}{projectID, label}
	h, err := contracts.HashHex(sum)
	if err != nil {
		return "", err
	}
	return "scopedef-" + h[:26], nil
}

func (r *Scopes) Get(ctx context.Context, projectID, label string) (scopeguard.Scope, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM scopes WHERE project_id = ? AND label = ?", projectID, label).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return scopeguard.Scope{}, ErrNotFound
	}
	if err != nil {
		return scopeguard.Scope{}, err
	}
	var s scopeguard.Scope
	return s, unmarshal(data, &s)
}

type Snapshots struct {
	db *DB
}

func (d *DB) Snapshots() *Snapshots {
	return &Snapshots{db: d}
}

func (r *Snapshots) Put(ctx context.Context, snap scopeguard.Snapshot) error {
	data, err := marshal(snap)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO scopesnapshots(id, project_id, authorization_id, mode, hash, data, compiled_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(hash) DO NOTHING",
		snap.ID, snap.ProjectID, snap.AuthorizationID, string(snap.Mode), snap.Hash, data, timeString(snap.CompiledAt))
	return err
}

func (r *Snapshots) Get(ctx context.Context, id string) (scopeguard.Snapshot, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM scopesnapshots WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return scopeguard.Snapshot{}, ErrNotFound
	}
	if err != nil {
		return scopeguard.Snapshot{}, err
	}
	var s scopeguard.Snapshot
	return s, unmarshal(data, &s)
}

func (r *Snapshots) ByHash(ctx context.Context, hash string) (scopeguard.Snapshot, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM scopesnapshots WHERE hash = ?", hash).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return scopeguard.Snapshot{}, ErrNotFound
	}
	if err != nil {
		return scopeguard.Snapshot{}, err
	}
	var s scopeguard.Snapshot
	return s, unmarshal(data, &s)
}
