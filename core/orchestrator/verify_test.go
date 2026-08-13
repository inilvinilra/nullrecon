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
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
	"github.com/nullrecon/nullrecon/platform/database"
)

func TestVerifyCandidatesUpgradesOnActiveCorroboration(t *testing.T) {
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
	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-verify")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}

	ast := asset.New(project.ID, asset.KindHostname, "app.acme.test")
	ast.Class = asset.ClassActive
	stored, err := db.Assets().Upsert(ctx, ast)
	if err != nil {
		t.Fatal(err)
	}
	assetID := stored.ID
	cve := "CVE-2021-44228"
	key := "vuln:" + cve + ":" + assetID
	passive := finding.Finding{
		ID:             "fnd-passive",
		ProjectID:      project.ID,
		Title:          cve + " version-inferred",
		State:          finding.StatePotential,
		Severity:       finding.SevCritical,
		Confidence:     finding.Confidence{Parse: 1, Ownership: 1, Freshness: 0.7, Fingerprint: 0.9, Version: 0.9, Value: 0.59},
		AssetIDs:       []string{assetID},
		FingerprintKey: key,
		FirstSeen:      now,
		LastSeen:       now,
	}
	if err := db.Findings().Upsert(ctx, passive); err != nil {
		t.Fatal(err)
	}

	beforeOut, _, err := orch.verifyCandidates(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Upgraded int `json:"upgraded"`
	}
	json.Unmarshal(beforeOut, &before)
	if before.Upgraded != 0 {
		t.Fatalf("no active corroboration yet, expected 0 upgrades, got %d", before.Upgraded)
	}

	tmplCand := vulnerability.New(project.ID, assetID, vulnerability.MatchTemplate, "template", now)
	tmplCand.CVE = cve
	tmplCand.State = vulnerability.CandVerified
	if err := db.VulnCandidates().Upsert(ctx, tmplCand); err != nil {
		t.Fatal(err)
	}

	afterOut, _, err := orch.verifyCandidates(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Upgraded int `json:"upgraded"`
	}
	json.Unmarshal(afterOut, &after)
	if after.Upgraded != 1 {
		t.Fatalf("active template corroboration must upgrade the passive finding, got %d (%s)", after.Upgraded, afterOut)
	}

	got, err := db.Findings().Get(ctx, "fnd-passive")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != finding.StateConfirmed {
		t.Fatalf("actively-corroborated finding must become confirmed, got %s (value %.2f)", got.State, got.Confidence.Value)
	}
	if got.Confidence.ActiveVerification < 0.8 {
		t.Fatalf("active verification must be raised, got %.2f", got.Confidence.ActiveVerification)
	}
}
