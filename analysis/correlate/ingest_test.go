package correlate

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/providers/registry"
)

func setup(t *testing.T) (*Ingestor, *database.DB, string) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	if err := db.Projects().Put(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err := db.Authorizations().Put(context.Background(), authz); err != nil {
		t.Fatal(err)
	}
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.CIDRs = []string{"192.0.2.0/28"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	return NewIngestor(db, snap), db, project.ID
}

func TestIngestCreatesAssetsClaimsRelations(t *testing.T) {
	in, db, projectID := setup(t)
	ctx := context.Background()
	records := []registry.Record{
		{Kind: "service", Value: "192.0.2.10", Fields: map[string]string{"ip": "192.0.2.10", "host": "WWW.Example.COM", "port": "443"}, FreshnessClass: "daily", ObservedAt: time.Now().UTC()},
	}
	stats, err := in.Ingest(ctx, projectID, "shodan", records)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 2 || stats.Claims != 2 || stats.Relations != 1 {
		t.Fatalf("bad stats: %+v", stats)
	}
	host, err := db.Assets().ByValue(ctx, projectID, asset.KindHostname, "www.example.com")
	if err != nil {
		t.Fatalf("normalized hostname asset must exist: %v", err)
	}
	if host.Class != asset.ClassActive {
		t.Fatalf("in-scope host must be active, got %s", host.Class)
	}
	rels, err := db.Assets().Relations(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].Kind != asset.RelResolvesTo {
		t.Fatalf("expected resolvesto relation: %+v", rels)
	}
	claims, err := db.Assets().Claims(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Source != "shodan" {
		t.Fatalf("claim provenance missing: %+v", claims)
	}
}

func TestIngestMergesEquivalentAssets(t *testing.T) {
	in, db, projectID := setup(t)
	ctx := context.Background()
	rec := registry.Record{Kind: "service", Fields: map[string]string{"ip": "192.0.2.10"}, FreshnessClass: "daily", ObservedAt: time.Now().UTC()}
	if _, err := in.Ingest(ctx, projectID, "shodan", []registry.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Ingest(ctx, projectID, "censys", []registry.Record{rec}); err != nil {
		t.Fatal(err)
	}
	a, err := db.Assets().ByValue(ctx, projectID, asset.KindIP, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := db.Assets().Claims(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	for _, c := range claims {
		sources[c.Source] = true
	}
	if len(sources) != 2 {
		t.Fatalf("merged asset must preserve both source claims, got %v", sources)
	}
	assets, err := db.Assets().List(ctx, projectID, asset.KindIP)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("equivalent assets must merge to one row, got %d", len(assets))
	}
}

func TestOutOfScopeStaysUnknown(t *testing.T) {
	in, db, projectID := setup(t)
	ctx := context.Background()
	rec := registry.Record{Kind: "service", Fields: map[string]string{"ip": "198.51.100.99", "host": "unrelated.net"}, FreshnessClass: "daily", ObservedAt: time.Now().UTC()}
	if _, err := in.Ingest(ctx, projectID, "fofa", []registry.Record{rec}); err != nil {
		t.Fatal(err)
	}
	host, err := db.Assets().ByValue(ctx, projectID, asset.KindDomain, "unrelated.net")
	if err != nil {
		t.Fatal(err)
	}
	if host.Class != asset.ClassUnknown {
		t.Fatalf("out-of-scope asset must stay unknown, got %s", host.Class)
	}
}

func TestMalformedRecordSkipped(t *testing.T) {
	in, _, projectID := setup(t)
	stats, err := in.Ingest(context.Background(), projectID, "netlas", []registry.Record{{Kind: "service", Fields: map[string]string{"ip": "not-an-ip"}}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Skipped != 1 || stats.Assets != 0 {
		t.Fatalf("malformed record must be skipped: %+v", stats)
	}
}

func TestFreshnessDecay(t *testing.T) {
	now := time.Now().UTC()
	current := FreshnessScore("daily", now.Add(-time.Hour), now)
	stale := FreshnessScore("daily", now.Add(-30*24*time.Hour), now)
	if current <= stale {
		t.Fatal("freshness must decay with age")
	}
	if FreshnessLabel("daily", now.Add(-time.Hour), now) != "current" {
		t.Fatal("recent observation must be current")
	}
	if FreshnessLabel("daily", now.Add(-90*24*time.Hour), now) != "historical" {
		t.Fatal("old observation must be historical")
	}
	if FreshnessScore("static", now.Add(-10*365*24*time.Hour), now) != 1 {
		t.Fatal("static class must not decay")
	}
	if FreshnessScore("daily", time.Time{}, now) >= 0.5 {
		t.Fatal("missing observation time must score low")
	}
}
