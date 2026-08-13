package orchestrator

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/platform/database"
)

func TestBuildEvidenceChainsAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"acme.test"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-evd")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}

	for i, key := range []string{"a", "b", "c"} {
		f := finding.Finding{
			ID:             "fnd-" + key,
			ProjectID:      project.ID,
			Title:          "finding " + key,
			State:          finding.StateConfirmed,
			Severity:       finding.SevHigh,
			Confidence:     finding.Confidence{Value: 0.9},
			FingerprintKey: "exposure:sig:" + key,
			FirstSeen:      now,
			LastSeen:       now.Add(time.Duration(i) * time.Second),
		}
		if err := db.Findings().Upsert(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	firstOut, _, err := orch.buildEvidence(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var first struct {
		EvidenceBuilt int    `json:"evidenceBuilt"`
		ChainHead     string `json:"chainHead"`
	}
	json.Unmarshal(firstOut, &first)
	if first.EvidenceBuilt != 3 {
		t.Fatalf("expected 3 evidence records, got %d", first.EvidenceBuilt)
	}
	if first.ChainHead == snap.Hash {
		t.Fatal("chain head must advance beyond the snapshot seed")
	}

	items, err := db.Evidence().ForRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 stored evidence rows, got %d", len(items))
	}
	prev := snap.Hash
	for _, e := range items {
		if e.Hashes["prev"] != prev {
			t.Fatalf("evidence chain broken: prev %q != expected %q", e.Hashes["prev"], prev)
		}
		if e.FindingID == "" || e.StorageRef == "" {
			t.Fatalf("evidence must link a finding and a storage ref: %+v", e)
		}
		prev = e.Hashes["chain"]
	}

	secondOut, _, err := orch.buildEvidence(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var second struct {
		EvidenceBuilt int `json:"evidenceBuilt"`
		Skipped       int `json:"skipped"`
	}
	json.Unmarshal(secondOut, &second)
	if second.EvidenceBuilt != 0 || second.Skipped != 3 {
		t.Fatalf("re-run must be idempotent: built=%d skipped=%d", second.EvidenceBuilt, second.Skipped)
	}
}
