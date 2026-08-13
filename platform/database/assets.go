package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/asset"
)

type Assets struct {
	db *DB
}

func (d *DB) Assets() *Assets {
	return &Assets{db: d}
}

func (r *Assets) Upsert(ctx context.Context, a asset.Asset) (asset.Asset, error) {
	data, err := marshal(a)
	if err != nil {
		return asset.Asset{}, err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO assets(id, project_id, kind, value, class, data, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(project_id, kind, value) DO UPDATE SET last_seen=excluded.last_seen, class=excluded.class, data=excluded.data",
		a.ID, a.ProjectID, string(a.Kind), a.Value, string(a.Class), data, timeString(a.FirstSeen), timeString(a.LastSeen))
	if err != nil {
		return asset.Asset{}, err
	}
	return r.ByValue(ctx, a.ProjectID, a.Kind, a.Value)
}

func (r *Assets) ByValue(ctx context.Context, projectID string, kind asset.Kind, value string) (asset.Asset, error) {
	var id, data string
	err := r.db.QueryRowContext(ctx, "SELECT id, data FROM assets WHERE project_id = ? AND kind = ? AND value = ?", projectID, string(kind), value).Scan(&id, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return asset.Asset{}, ErrNotFound
	}
	if err != nil {
		return asset.Asset{}, err
	}
	var a asset.Asset
	if err := unmarshal(data, &a); err != nil {
		return asset.Asset{}, err
	}
	a.ID = id
	return a, nil
}

func (r *Assets) Get(ctx context.Context, id string) (asset.Asset, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM assets WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return asset.Asset{}, ErrNotFound
	}
	if err != nil {
		return asset.Asset{}, err
	}
	var a asset.Asset
	if err := unmarshal(data, &a); err != nil {
		return asset.Asset{}, err
	}
	a.ID = id
	return a, nil
}

func (r *Assets) SetClass(ctx context.Context, id string, class asset.Class) error {
	a, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	a.Class = class
	data, err := marshal(a)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "UPDATE assets SET class = ?, data = ? WHERE id = ?", string(class), data, id)
	return err
}

func (r *Assets) List(ctx context.Context, projectID string, kind asset.Kind) ([]asset.Asset, error) {
	query := "SELECT id, data FROM assets WHERE project_id = ?"
	args := []any{projectID}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, string(kind))
	}
	query += " ORDER BY value"
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []asset.Asset
	for rows.Next() {
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		var a asset.Asset
		if err := unmarshal(data, &a); err != nil {
			return nil, err
		}
		a.ID = id
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *Assets) PutClaim(ctx context.Context, c asset.AssetClaim) error {
	if c.ID == "" {
		c.ID = contracts.NewID("clm")
	}
	if c.Kind == "" {
		c.Versioned = contracts.NewVersioned("assetclaim")
	}
	data, err := marshal(c)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO assetclaims(id, asset_id, project_id, source, source_id, observed_at, fetched_at, raw_hash, data) VALUES (?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(asset_id, source, source_id, observed_at) DO NOTHING",
		c.ID, c.AssetID, c.ProjectID, c.Source, c.SourceID, timeString(c.ObservedAt), timeString(c.FetchedAt), c.RawHash, data)
	return err
}

func (r *Assets) Claims(ctx context.Context, assetID string) ([]asset.AssetClaim, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM assetclaims WHERE asset_id = ? ORDER BY observed_at", assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []asset.AssetClaim
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c asset.AssetClaim
		if err := unmarshal(data, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Assets) PutRelation(ctx context.Context, rel asset.AssetRelation) error {
	if rel.ID == "" {
		rel.ID = contracts.NewID("rel")
	}
	if rel.Kind == "" {
		return errors.New("database: relation kind required")
	}
	if rel.Version == "" {
		rel.Versioned = contracts.NewVersioned("assetrelation")
	}
	data, err := marshal(rel)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO assetrelations(id, project_id, from_asset, to_asset, kind, data, observed_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(from_asset, to_asset, kind) DO UPDATE SET data=excluded.data",
		rel.ID, rel.ProjectID, rel.FromAssetID, rel.ToAssetID, string(rel.Kind), data, timeString(rel.ObservedAt))
	return err
}

func (r *Assets) Relations(ctx context.Context, assetID string) ([]asset.AssetRelation, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM assetrelations WHERE from_asset = ? OR to_asset = ?", assetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []asset.AssetRelation
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var rel asset.AssetRelation
		if err := unmarshal(data, &rel); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}
