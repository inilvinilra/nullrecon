package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
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

func discoveryTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("ADMIN CONTROL PANEL unique administrative body content that is distinct"))
			return
		}
		w.Write([]byte("standard not found placeholder page for this application"))
	}))
}

func hostPort(t *testing.T, url string) (string, int) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(url, "http://"), ":")
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return parts[0], port
}

func setupDiscovery(t *testing.T, mode policy.Mode, grant bool) (*Orchestrator, *workflow.NodeContext, string, *database.DB) {
	t.Helper()
	srv := discoveryTestServer()
	t.Cleanup(srv.Close)
	host, port := hostPort(t, srv.URL)

	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{string(mode)}, now.Add(-time.Hour), now.Add(time.Hour))

	ast := asset.New(project.ID, asset.KindIP, host)
	ast.Class = asset.ClassActive
	stored, err := db.Assets().Upsert(ctx, ast)
	if err != nil {
		t.Fatal(err)
	}
	seed := endpoint.New(project.ID, stored.ID, srv.URL+"/", "GET", "webprobe", now)
	seed.Status = 200
	if err := db.Endpoints().Upsert(ctx, seed); err != nil {
		t.Fatal(err)
	}

	scope := scopeguard.NewScope()
	scope.IPs = []string{host}
	scope.Ports = []int{port}
	scope.Protocols = []string{"tcp"}
	if grant {
		scope.ScanClasses = []string{"contentdiscovery"}
	}
	snap, err := scopeguard.Compile(project, authz, scope, mode, now)
	if err != nil {
		t.Fatal(err)
	}

	run := scanrun.New(project.ID, "baseline", "v1", string(mode), snap.ID, snap.Hash, "idem-1")
	orch := New(Deps{DB: db})
	probeInput, _ := json.Marshal(map[string]any{"open": []openPort{{AssetID: stored.ID, Host: host, Port: port}}})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{"ProbeHosts": probeInput}}
	return orch, nc, stored.ID, db
}

func TestContentDiscoveryStoresCandidates(t *testing.T) {
	ctx := context.Background()
	orch, nc, assetID, db := setupDiscovery(t, policy.ModeAuthorizedTest, true)

	planOut, _, err := orch.planContentDiscovery(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	nc.Input["PlanContentDiscovery"] = planOut

	runOut, _, err := orch.runContentDiscovery(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Candidates int `json:"candidates"`
	}
	if err := json.Unmarshal(runOut, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Candidates == 0 {
		t.Fatalf("expected stored candidates, got %s", runOut)
	}

	eps, err := db.Endpoints().ForAsset(ctx, assetID)
	if err != nil {
		t.Fatal(err)
	}
	foundAdmin := false
	for _, ep := range eps {
		if strings.HasSuffix(ep.URL, "/admin") && ep.Source == "contentdiscovery" {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Fatalf("admin candidate must be stored as an endpoint: %+v", eps)
	}
}

func TestContentDiscoveryFailsClosedWithoutAuthorization(t *testing.T) {
	ctx := context.Background()
	orch, nc, _, _ := setupDiscovery(t, policy.ModeSafeActive, false)

	planOut, _, err := orch.planContentDiscovery(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Targets []discoveryTarget `json:"targets"`
	}
	if err := json.Unmarshal(planOut, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("safeactive mode must not authorize content discovery targets: %+v", plan.Targets)
	}
}
