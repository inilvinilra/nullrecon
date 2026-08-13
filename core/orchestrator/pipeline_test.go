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
	"github.com/nullrecon/nullrecon/domain/technology"
	"github.com/nullrecon/nullrecon/platform/database"
)

func TestEnrichVulnerabilitiesVersionInferredNeverConfirmed(t *testing.T) {
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
	ast := asset.New(project.ID, asset.KindHostname, "app.acme.test")
	ast.Class = asset.ClassActive
	stored, err := db.Assets().Upsert(ctx, ast)
	if err != nil {
		t.Fatal(err)
	}

	tech := technology.New(project.ID, stored.ID, "log4j", "fingerprint", now)
	tech.Vendor = "apache"
	tech.Version = "2.14.1"
	tech.Confidence = 0.9
	if err := db.Technologies().Upsert(ctx, tech); err != nil {
		t.Fatal(err)
	}

	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"acme.test"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-vuln")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}

	enrichOut, _, err := orch.enrichVulnerabilities(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Candidates int `json:"candidates"`
		KEV        int `json:"kev"`
	}
	if err := json.Unmarshal(enrichOut, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Candidates == 0 {
		t.Fatalf("expected a Log4Shell candidate for log4j 2.14.1, got %s", enrichOut)
	}
	if summary.KEV == 0 {
		t.Fatal("Log4Shell is KEV-listed and must be flagged")
	}

	cands, err := db.VulnCandidates().ForProject(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 || cands[0].CVE != "CVE-2021-44228" {
		t.Fatalf("expected stored Log4Shell candidate, got %+v", cands)
	}

	findings, err := db.Findings().List(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	var vuln *finding.Finding
	for i := range findings {
		if findings[i].WeaknessClass == "vulnerability:productversion" {
			vuln = &findings[i]
		}
	}
	if vuln == nil {
		t.Fatalf("expected a version-inferred vulnerability finding: %+v", findings)
	}
	if vuln.State == finding.StateConfirmed {
		t.Fatalf("version-inferred finding without active verification must never be confirmed, got %s", vuln.State)
	}
	if vuln.Severity != finding.SevCritical {
		t.Fatalf("Log4Shell should map to critical severity, got %s", vuln.Severity)
	}

	scoreOut, _, err := orch.scoreConfidence(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	rescored, err := db.Findings().Get(ctx, vuln.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rescored.State == finding.StateConfirmed {
		t.Fatalf("ScoreConfidence must not confirm a version-inferred finding: %s", scoreOut)
	}
}
