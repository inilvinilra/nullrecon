package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrateIdempotent(t *testing.T) {
	db := openTemp(t)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("second migration run must be a no-op: %v", err)
	}
}

func TestProjectRoundtrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	got, err := db.Projects().BySlug(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != project.ID || got.Name != "Acme" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, err := db.Projects().BySlug(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing slug must return ErrNotFound, got %v", err)
	}
}

func TestProjectPutIdempotent(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	project.Name = "Acme Renamed"
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	got, err := db.Projects().Get(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Acme Renamed" {
		t.Fatal("idempotent put must update by primary key")
	}
}

func TestSnapshotPutIdempotentByHash(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "program", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err := db.Authorizations().Put(ctx, authz); err != nil {
		t.Fatal(err)
	}
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Snapshots().Put(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if err := db.Snapshots().Put(ctx, snap); err != nil {
		t.Fatalf("duplicate snapshot hash must be a no-op: %v", err)
	}
	got, err := db.Snapshots().ByHash(ctx, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != snap.Hash || got.Mode != policy.ModeSafeActive {
		t.Fatalf("snapshot roundtrip mismatch: %+v", got)
	}
}

func TestScopeRoundtrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	if _, err := db.Scopes().Put(ctx, project.ID, "default", scope); err != nil {
		t.Fatal(err)
	}
	got, err := db.Scopes().Get(ctx, project.ID, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RootDomains) != 1 || got.RootDomains[0] != "example.com" {
		t.Fatalf("scope roundtrip mismatch: %+v", got)
	}
}
