package auditlog

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/nullrecon/nullrecon/platform/database"
)

func openTemp(t *testing.T) (*Log, *database.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), db
}

func TestAppendAndVerify(t *testing.T) {
	log, _ := openTemp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := log.Append(ctx, "prj-1", "cli", "action", "", "reason", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("chain must verify: %v", err)
	}
	entries, err := log.List(ctx, "prj-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	if entries[0].PrevHash != "genesis" {
		t.Fatal("first entry must link to genesis")
	}
}

func TestTamperDetection(t *testing.T) {
	log, db := openTemp(t)
	ctx := context.Background()
	e, err := log.Append(ctx, "prj-1", "cli", "action", "", "reason", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, "prj-1", "cli", "action2", "", "reason", ""); err != nil {
		t.Fatal(err)
	}
	var data string
	if err := db.QueryRowContext(ctx, "SELECT data FROM auditentries WHERE id = ?", e.ID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var forged Entry
	if err := json.Unmarshal([]byte(data), &forged); err != nil {
		t.Fatal(err)
	}
	forged.Reason = "forged"
	forgedData, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE auditentries SET data = ? WHERE id = ?", string(forgedData), e.ID); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(ctx); err == nil {
		t.Fatal("tampered chain must fail verification")
	}
}

func TestHashCoversActorAndAction(t *testing.T) {
	log, _ := openTemp(t)
	ctx := context.Background()
	e1, err := log.Append(ctx, "prj-1", "alice", "reveal", "target", "r", "")
	if err != nil {
		t.Fatal(err)
	}
	e2, err := log.Append(ctx, "prj-1", "bob", "reveal", "target", "r", "")
	if err != nil {
		t.Fatal(err)
	}
	if e1.Hash == e2.Hash {
		t.Fatal("distinct actors must produce distinct hashes")
	}
}
