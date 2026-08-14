package orchestrator

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/domain/scanrun"
	"github.com/nullrecon/nullrecon/platform/database"
)

// The orchestrated port scan must grab service banners: probeHosts already
// reads p.Banner (storing BannerHash/Attrs and forwarding it downstream), so
// the engine has to be built WithBanners. This guards against a regression
// where the flag is dropped and every workflow service silently loses its
// banner, starving fingerprinting and honeypot detection.
func TestProbeHostsCapturesServiceBanners(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte(banner + "\r\n"))
			conn.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

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
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
	ast := asset.New(project.ID, asset.KindIP, host)
	ast.Class = asset.ClassActive
	stored, err := db.Assets().Upsert(ctx, ast)
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeguard.NewScope()
	scope.IPs = []string{host}
	scope.Ports = []int{port}
	scope.Protocols = []string{"tcp"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	run := scanrun.New(project.ID, "baseline", "v1", string(policy.ModeSafeActive), snap.ID, snap.Hash, "idem-1")
	orch := New(Deps{DB: db})
	planInput, _ := json.Marshal(map[string]any{
		"targets": []probeTarget{{AssetID: stored.ID, IP: host, Ports: []int{port}}},
	})
	nc := &workflow.NodeContext{DB: db, Snapshot: snap, Run: run, Input: map[string]json.RawMessage{"PlanSafeActive": planInput}}

	out, _, err := orch.probeHosts(ctx, nc)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Open []struct {
			Port   int    `json:"port"`
			Banner string `json:"banner"`
		} `json:"open"`
	}
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Open) == 0 {
		t.Fatalf("open port must be reported: %s", out)
	}
	if summary.Open[0].Banner == "" {
		t.Fatalf("orchestrated port scan must capture the service banner, got empty: %s", out)
	}

	services, err := db.Services().ForAsset(ctx, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundBanner := false
	for _, svc := range services {
		if svc.Attrs["banner"] != "" && svc.BannerHash != "" {
			foundBanner = true
		}
	}
	if !foundBanner {
		t.Fatalf("stored service must persist the captured banner: %+v", services)
	}
}
