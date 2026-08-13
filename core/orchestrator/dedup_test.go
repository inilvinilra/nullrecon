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

func TestDeduplicateSignalsClustersCrossPath(t *testing.T) {
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
	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-dedup")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}

	asset := "ast-1"
	cve := "CVE-2021-44228"
	versionFinding := finding.Finding{
		ID:             "fnd-version",
		ProjectID:      project.ID,
		Title:          "version-inferred",
		State:          finding.StateConfirmed,
		Severity:       finding.SevCritical,
		Confidence:     finding.Confidence{Value: 0.93},
		AssetIDs:       []string{asset},
		FingerprintKey: "vuln:" + cve + ":" + asset,
		FirstSeen:      now, LastSeen: now,
	}
	templateFinding := finding.Finding{
		ID:             "fnd-template",
		ProjectID:      project.ID,
		Title:          "template match",
		State:          finding.StateConfirmed,
		Severity:       finding.SevCritical,
		Confidence:     finding.Confidence{Value: 0.9},
		AssetIDs:       []string{asset},
		FingerprintKey: "template:log4shell-probe:" + asset,
		FirstSeen:      now, LastSeen: now,
	}
	for _, f := range []finding.Finding{versionFinding, templateFinding} {
		if err := db.Findings().Upsert(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	orch.tmplCVEResolver = func() map[string]string { return map[string]string{"log4shell-probe": cve} }

	dedupOut, _, err := orch.deduplicateSignals(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Clusters   int `json:"clusters"`
		Duplicates int `json:"duplicates"`
	}
	json.Unmarshal(dedupOut, &summary)
	if summary.Clusters != 1 || summary.Duplicates != 1 {
		t.Fatalf("cross-path findings must form 1 cluster with 1 duplicate: %s", dedupOut)
	}

	dup, err := db.Findings().Get(ctx, "fnd-template")
	if err != nil {
		t.Fatal(err)
	}
	if dup.State != finding.StateDuplicate {
		t.Fatalf("lower-confidence finding must be marked duplicate, got %s", dup.State)
	}
	rels, err := db.Findings().Relations(ctx, "fnd-template")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].ToID != "fnd-version" || rels[0].Kind != finding.FindingDuplicateOf {
		t.Fatalf("expected duplicateof relation to canonical: %+v", rels)
	}
}
