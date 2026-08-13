package database

import (
	"context"
	"time"
)

type Usage struct {
	Provider string `json:"provider"`
	Credits  int64  `json:"credits"`
	Requests int64  `json:"requests"`
}

type UsageStore struct {
	db *DB
}

func (d *DB) Usage() *UsageStore {
	return &UsageStore{db: d}
}

func windowStart(t time.Time) string {
	return t.UTC().Format("2006-01")
}

func (s *UsageStore) Record(ctx context.Context, provider string, credits, requests int64) error {
	window := windowStart(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO providerusage(id, provider, project_id, credits, requests, window_start, data)
		VALUES (?, ?, '', ?, ?, ?, '{}')
		ON CONFLICT(provider, project_id, window_start)
		DO UPDATE SET credits = credits + excluded.credits, requests = requests + excluded.requests`,
		"usage-"+provider+"-"+window, provider, credits, requests, window)
	return err
}

func (s *UsageStore) Summary(ctx context.Context) ([]Usage, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT provider, SUM(credits), SUM(requests) FROM providerusage GROUP BY provider ORDER BY provider")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.Provider, &u.Credits, &u.Requests); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type ProviderConfig struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	SecretRef string `json:"secretRef,omitempty"`
}

type ProviderConfigs struct {
	db *DB
}

func (d *DB) ProviderConfigs() *ProviderConfigs {
	return &ProviderConfigs{db: d}
}

func (s *ProviderConfigs) Put(ctx context.Context, name, adapterVersion string, enabled bool, secretRef string) error {
	data, err := marshal(ProviderConfig{Name: name, Enabled: enabled, SecretRef: secretRef})
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO providers(name, adapter_version, enabled, config, updated_at) VALUES (?,?,?,?,?) "+
			"ON CONFLICT(name) DO UPDATE SET adapter_version=excluded.adapter_version, enabled=excluded.enabled, config=excluded.config, updated_at=excluded.updated_at",
		name, adapterVersion, boolInt(enabled), data, timeString(time.Now()))
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *ProviderConfigs) Get(ctx context.Context, name string) (ProviderConfig, error) {
	var data string
	err := s.db.QueryRowContext(ctx, "SELECT config FROM providers WHERE name = ?", name).Scan(&data)
	if err != nil {
		return ProviderConfig{}, err
	}
	var cfg ProviderConfig
	return cfg, unmarshal(data, &cfg)
}
