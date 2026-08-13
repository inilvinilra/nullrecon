package webprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

func snapshotForHost(t *testing.T, hosts []string, ports []int) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	scope := scopeguard.NewScope()
	for _, h := range hosts {
		if _, err := netip.ParseAddr(h); err == nil {
			scope.IPs = append(scope.IPs, h)
		} else {
			scope.RootDomains = append(scope.RootDomains, h)
		}
	}
	scope.Ports = ports
	scope.Protocols = []string{"tcp"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func serverHostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")
	if len(parts) != 2 {
		parts = strings.Split(strings.TrimPrefix(srv.URL, "https://"), ":")
	}
	var port int
	fmt.Sscanf(parts[1], "%d", &port)
	return parts[0], port
}

func TestProbeCapturesMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write([]byte("fake-icon-bytes"))
			return
		}
		w.Header().Set("Server", "nginx/1.25.0")
		w.Header().Set("Set-Cookie", "session=secretvalue123")
		w.Write([]byte("<html><head><title>Test Page</title></head><body>hello</body></html>"))
	}))
	defer srv.Close()
	host, port := serverHostPort(t, srv)
	snap := snapshotForHost(t, []string{host}, []int{port})
	red, _ := redaction.New(nil)
	e := New(snap, nil, red)
	res, err := e.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.Title != "Test Page" {
		t.Fatalf("bad result: %+v", res)
	}
	if res.Headers["server"] != "nginx/1.25.0" {
		t.Fatalf("headers must be captured: %+v", res.Headers)
	}
	if strings.Contains(res.Headers["set-cookie"], "secretvalue123") {
		t.Fatal("cookie value must be redacted")
	}
	if res.FaviconMMH3 == nil || res.FaviconSHA256 == "" {
		t.Fatal("favicon hashes must be captured")
	}
	if res.ContentHash == "" || res.BodyBytes == 0 {
		t.Fatal("content hash and size must be captured")
	}
}

func TestProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := serverHostPort(t, srv)
	snap := snapshotForHost(t, []string{host}, []int{port})
	e := New(snap, nil, nil)
	res, err := e.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.TLS == nil {
		t.Fatal("tls info must be captured")
	}
	if res.TLS.Version == "" || len(res.TLS.SANs) == 0 {
		t.Fatalf("bad tls info: %+v", res.TLS)
	}
	if res.TLS.VerifyError == "" {
		t.Fatal("self-signed cert must record a verification error")
	}
	_ = tls.VersionTLS13
}

func TestOutOfScopeRedirectBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()
	host, port := serverHostPort(t, srv)
	snap := snapshotForHost(t, []string{host}, []int{port, 80})
	e := New(snap, nil, nil)
	res, err := e.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.BlockedRedirect == "" {
		t.Fatalf("out-of-scope redirect must be blocked and recorded: %+v", res)
	}
}

func TestInScopeRedirectFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.Write([]byte("<title>Final</title>"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()
	host, port := serverHostPort(t, srv)
	snap := snapshotForHost(t, []string{host}, []int{port})
	e := New(snap, nil, nil)
	res, err := e.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.Title != "Final" || len(res.Hops) == 0 {
		t.Fatalf("in-scope redirect must be followed: %+v", res)
	}
}

func TestOutOfScopeTargetRejected(t *testing.T) {
	snap := snapshotForHost(t, []string{"example.com"}, []int{443})
	e := New(snap, nil, nil)
	_, err := e.Probe(context.Background(), "http://169.254.169.254/")
	if err == nil {
		t.Fatal("out-of-scope target must be rejected before any request")
	}
}
