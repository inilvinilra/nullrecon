package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/endpoint"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/platform/database"
)

func TestRunAllowedChecksStoresExposureFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/a/b.git\n"))
			return
		}
		w.Write([]byte("<html><body>not found</body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

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
	ast := asset.New(project.ID, asset.KindIP, host)
	ast.Class = asset.ClassActive
	stored, err := db.Assets().Upsert(ctx, ast)
	if err != nil {
		t.Fatal(err)
	}
	seed := endpoint.New(project.ID, stored.ID, srv.URL+"/", "GET", "webprobe", now)
	if err := db.Endpoints().Upsert(ctx, seed); err != nil {
		t.Fatal(err)
	}

	scope := scopeguard.NewScope()
	scope.IPs = []string{host}
	scope.Ports = []int{port}
	scope.Protocols = []string{"tcp"}
	scope.ScanClasses = []string{"vulntemplate"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}

	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-checks")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}

	genOut, _, err := orch.generateVulnerabilityCandidates(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	nc.Input["GenerateVulnerabilityCandidates"] = genOut

	runOut, _, err := orch.runAllowedChecks(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Exposures int `json:"exposures"`
	}
	if err := json.Unmarshal(runOut, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Exposures == 0 {
		t.Fatalf("expected stored exposures, got %s", runOut)
	}

	findings, err := db.Findings().List(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.WeaknessClass == "exposure:leak" && f.State == "confirmed" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("git-config exposure must produce a confirmed high finding: %+v", findings)
	}

	exposures, err := db.Exposures().ForProject(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(exposures) == 0 {
		t.Fatal("exposure record must be stored")
	}
}

func TestRunAllowedChecksIdempotentFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.Write([]byte("[core]\n[remote \"origin\"]\n\turl = https://example.com/a/b.git\n"))
			return
		}
		w.Write([]byte("<html><body>nope</body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

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
	ast := asset.New(project.ID, asset.KindIP, host)
	ast.Class = asset.ClassActive
	stored, _ := db.Assets().Upsert(ctx, ast)
	seed := endpoint.New(project.ID, stored.ID, srv.URL+"/", "GET", "webprobe", now)
	db.Endpoints().Upsert(ctx, seed)
	scope := scopeguard.NewScope()
	scope.IPs = []string{host}
	scope.Ports = []int{port}
	scope.Protocols = []string{"tcp"}
	scope.ScanClasses = []string{"vulntemplate"}
	snap, _ := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	run := scanrun.New(project.ID, "baseline", "v1", "authorizedtest", snap.ID, snap.Hash, "idem-checks-2")
	orch := New(Deps{DB: db})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{}}
	genOut, _, _ := orch.generateVulnerabilityCandidates(ctx, nc)
	nc.Input["GenerateVulnerabilityCandidates"] = genOut

	for i := 0; i < 2; i++ {
		if _, _, err := orch.runAllowedChecks(ctx, nc); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := db.Findings().List(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.FingerprintKey == "exposure:git-config:"+stored.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("re-running checks must not duplicate the finding, got %d", count)
	}
}
