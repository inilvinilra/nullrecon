package contentdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func snapshotForHost(t *testing.T, host string, customize ...func(*scopeguard.Scope)) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	scope := scopeguard.NewScope()
	if _, err := netip.ParseAddr(host); err == nil {
		scope.IPs = append(scope.IPs, host)
	} else {
		scope.RootDomains = append(scope.RootDomains, host)
	}
	scope.Protocols = []string{"tcp"}
	for _, fn := range customize {
		fn(&scope)
	}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	trimmed := strings.TrimPrefix(srv.URL, "http://")
	return strings.Split(trimmed, ":")[0]
}

const catchAllBody = "standard not found placeholder page for this application"

func discoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Write([]byte("ADMIN CONTROL PANEL unique administrative interface body content here"))
		case "/login":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		case "/old":
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
		default:
			w.Write([]byte(catchAllBody))
		}
	}))
}

func TestScanDetectsCatchAllAndCandidates(t *testing.T) {
	srv := discoveryServer()
	defer srv.Close()
	snap := snapshotForHost(t, hostOf(t, srv))
	e := New(snap, nil)
	opt := Options{Words: []string{"admin", "login", "old", "images", "css"}}
	res, err := e.Scan(context.Background(), srv.URL, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Baseline.CatchAll {
		t.Fatalf("catch-all soft-404 must be detected: %+v", res.Baseline)
	}
	classByPath := map[string]string{}
	for _, h := range res.Hits {
		classByPath[h.Path] = h.Class
	}
	if classByPath["admin"] != classCandidate {
		t.Fatalf("admin must be a candidate, got %q (%+v)", classByPath["admin"], res.Hits)
	}
	if classByPath["login"] != classCandidate {
		t.Fatalf("login (401) must be a candidate, got %q", classByPath["login"])
	}
	if classByPath["old"] != classRedirect {
		t.Fatalf("old must be a redirect, got %q", classByPath["old"])
	}
	if classByPath["images"] != classNoise {
		t.Fatalf("images must be soft-404 noise, got %q", classByPath["images"])
	}
	if classByPath["css"] != classNoise {
		t.Fatalf("css must be soft-404 noise, got %q", classByPath["css"])
	}
}

func TestScanRespectsBudget(t *testing.T) {
	srv := discoveryServer()
	defer srv.Close()
	snap := snapshotForHost(t, hostOf(t, srv))
	budget := budgetguard.New("test", budgetguard.Budget{budgetguard.DimRequests: 2}, nil)
	e := New(snap, budget)
	opt := Options{Words: []string{"a", "b", "c", "d", "e", "f", "g", "h"}, CalibrateProbes: 1}
	res, err := e.Scan(context.Background(), srv.URL, opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocked == 0 {
		t.Fatalf("budget exhaustion must block excess requests: %+v", res)
	}
	if res.Requested > 2 {
		t.Fatalf("request budget of 2 must not be exceeded, made %d", res.Requested)
	}
}

func TestScanBlocksOutOfScopePath(t *testing.T) {
	srv := discoveryServer()
	defer srv.Close()
	snap := snapshotForHost(t, hostOf(t, srv), func(s *scopeguard.Scope) {
		s.DeniedPaths = []string{"/secret"}
	})
	e := New(snap, nil)
	opt := Options{Words: []string{"secret", "public"}, CalibrateProbes: 1}
	res, err := e.Scan(context.Background(), srv.URL, opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocked == 0 {
		t.Fatalf("denied path must be blocked before request: %+v", res)
	}
}
