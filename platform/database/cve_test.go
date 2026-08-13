package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/domain/cve"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "cve.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestCVEKnowledgeUpsertAndForProduct(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	rec := cve.Record{
		CVE:       "CVE-2021-44228",
		CVSSScore: 10.0,
		Severity:  "critical",
		KEV:       true,
		Source:    "nvd",
		UpdatedAt: time.Now().UTC(),
		Products:  []cve.Affected{{Vendor: "apache", Product: "log4j", RangeStartIncl: "2.0", RangeEndExcl: "2.15.0"}},
	}
	if err := db.CVEKnowledge().Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.CVEKnowledge().Get(ctx, "cve-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.CVSSScore != 10.0 || !got.KEV {
		t.Fatalf("bad get: %+v (ok=%v)", got, ok)
	}
	forProduct, err := db.CVEKnowledge().ForProduct(ctx, "log4j")
	if err != nil {
		t.Fatal(err)
	}
	if len(forProduct) != 1 || forProduct[0].CVE != "CVE-2021-44228" {
		t.Fatalf("ForProduct must find the cve: %+v", forProduct)
	}
}

func TestCVEKnowledgeUpsertReplacesProducts(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	rec := cve.Record{CVE: "CVE-1", Source: "nvd", UpdatedAt: time.Now().UTC(), Products: []cve.Affected{{Vendor: "v", Product: "old", ExactVersion: "1.0"}}}
	if err := db.CVEKnowledge().Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.Products = []cve.Affected{{Vendor: "v", Product: "new", ExactVersion: "2.0"}}
	if err := db.CVEKnowledge().Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if old, err := db.CVEKnowledge().ForProduct(ctx, "old"); err != nil || len(old) != 0 {
		t.Fatalf("stale product rows must be removed on re-upsert, got %d (err %v)", len(old), err)
	}
	if fresh, err := db.CVEKnowledge().ForProduct(ctx, "new"); err != nil || len(fresh) != 1 {
		t.Fatalf("new product row must exist, got %d (err %v)", len(fresh), err)
	}
}

func TestCVEKnowledgeStats(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	_ = db.CVEKnowledge().Upsert(ctx, cve.Record{CVE: "CVE-A", Source: "nvd", KEV: true, UpdatedAt: time.Now().UTC(), Products: []cve.Affected{{Vendor: "v", Product: "p", ExactVersion: "1"}}})
	_ = db.CVEKnowledge().Upsert(ctx, cve.Record{CVE: "CVE-B", Source: "nvd", UpdatedAt: time.Now().UTC()})
	stats, err := db.CVEKnowledge().Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["total"] != 2 || stats["kev"] != 1 || stats["productRanges"] != 1 {
		t.Fatalf("bad stats: %+v", stats)
	}
}
