package database

import (
	"context"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/endpoint"
)

type Endpoints struct {
	db *DB
}

func (d *DB) Endpoints() *Endpoints {
	return &Endpoints{db: d}
}

func (r *Endpoints) Upsert(ctx context.Context, e endpoint.Endpoint) error {
	if e.ID == "" {
		e.ID = contracts.NewID("ept")
	}
	if e.Version == "" {
		e.Versioned = contracts.NewVersioned("endpoint")
	}
	data, err := marshal(e)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO endpoints(id, project_id, asset_id, url, method, data, observed_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(asset_id, url, method) DO UPDATE SET data=excluded.data",
		e.ID, e.ProjectID, e.AssetID, e.URL, e.Method, data, timeString(e.ObservedAt))
	return err
}

func (r *Endpoints) ForAsset(ctx context.Context, assetID string) ([]endpoint.Endpoint, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM endpoints WHERE asset_id = ? ORDER BY url", assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []endpoint.Endpoint
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e endpoint.Endpoint
		if err := unmarshal(data, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
