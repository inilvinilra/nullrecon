package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nullrecon/nullrecon/domain/identity"
)

type APIKeys struct {
	db *DB
}

func (d *DB) APIKeys() *APIKeys {
	return &APIKeys{db: d}
}

func (r *APIKeys) Put(ctx context.Context, k identity.APIKey) error {
	revoked := 0
	if k.Revoked {
		revoked = 1
	}
	var lastUsed any
	if !k.LastUsedAt.IsZero() {
		lastUsed = timeString(k.LastUsedAt)
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO apikeys(id, name, key_hash, role, created_at, last_used_at, revoked) VALUES (?,?,?,?,?,?,?)",
		k.ID, k.Name, k.KeyHash, string(k.Role), timeString(k.CreatedAt), lastUsed, revoked)
	return err
}

func (r *APIKeys) ByHash(ctx context.Context, hash string) (identity.APIKey, bool, error) {
	var k identity.APIKey
	var role, createdAt string
	var lastUsed sql.NullString
	var revoked int
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, key_hash, role, created_at, last_used_at, revoked FROM apikeys WHERE key_hash = ?",
		hash).Scan(&k.ID, &k.Name, &k.KeyHash, &role, &createdAt, &lastUsed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.APIKey{}, false, nil
	}
	if err != nil {
		return identity.APIKey{}, false, err
	}
	k.Role = identity.Role(role)
	k.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if lastUsed.Valid {
		k.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsed.String)
	}
	k.Revoked = revoked == 1
	return k, true, nil
}

func (r *APIKeys) TouchUsed(ctx context.Context, id string, when time.Time) error {
	_, err := r.db.ExecContext(ctx, "UPDATE apikeys SET last_used_at = ? WHERE id = ?", timeString(when), id)
	return err
}

func (r *APIKeys) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE apikeys SET revoked = 1 WHERE id = ?", id)
	return err
}

func (r *APIKeys) List(ctx context.Context) ([]identity.APIKey, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name, role, created_at, last_used_at, revoked FROM apikeys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.APIKey
	for rows.Next() {
		var k identity.APIKey
		var role, createdAt string
		var lastUsed sql.NullString
		var revoked int
		if err := rows.Scan(&k.ID, &k.Name, &role, &createdAt, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		k.Role = identity.Role(role)
		k.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		if lastUsed.Valid {
			k.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsed.String)
		}
		k.Revoked = revoked == 1
		out = append(out, k)
	}
	return out, rows.Err()
}
