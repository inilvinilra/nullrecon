package database

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/nullrecon/nullrecon/migrations"
)

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	raw.SetMaxOpenConns(1)
	if err := raw.Ping(); err != nil {
		return nil, err
	}
	return &DB{raw}, nil
}

func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"); err != nil {
		return err
	}
	entries, err := migrations.Files.ReadDir(".")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("database: bad migration name %s", name)
		}
		var exists int
		if err := d.QueryRowContext(ctx, "SELECT COUNT(1) FROM schema_migrations WHERE version = ?", version).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("database: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
