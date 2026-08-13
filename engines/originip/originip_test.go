package originip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func TestNetworkMapLoadsAndClassifies(t *testing.T) {
	nm, err := LoadNetworkMap()
	if err != nil {
		t.Fatal(err)
	}
	if nm.Providers() < 20 {
		t.Fatalf("expected the full provider set, got %d", nm.Providers())
	}
	if nm.Ranges() < 3000 {
		t.Fatalf("expected thousands of ranges, got %d", nm.Ranges())
	}
	if provider, ok := nm.Classify("104.16.1.1"); !ok || provider != "cloudflare" {
		t.Fatalf("104.16.1.1 must classify as cloudflare, got %q %v", provider, ok)
	}
	if _, ok := nm.Classify("192.0.2.1"); ok {
		t.Fatal("documentation range 192.0.2.1 must not classify as any CDN")
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":     true,
		"192.0.2.10":  true,
		"10.0.0.1":    false,
		"127.0.0.1":   false,
		"169.254.0.1": false,
		"::1":         false,
		"not-an-ip":   false,
	}
	for ip, want := range cases {
		if got := isPublicIP(ip); got != want {
			t.Errorf("isPublicIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestMatchStateThresholds(t *testing.T) {
	if s := matchState(0.9, []string{"body", "title"}); s != "confirmed" {
		t.Fatalf("strong match must be confirmed, got %q", s)
	}
	if s := matchState(0.5, []string{"title"}); s != "likely" {
		t.Fatalf("title-only match must be likely, got %q", s)
	}
	if s := matchState(0.2, []string{"title_partial"}); s != "potential" {
		t.Fatalf("weak match must be potential, got %q", s)
	}
	if s := matchState(0.1, nil); s != "rejected" {
		t.Fatalf("no reasons must be rejected, got %q", s)
	}
}

func snapshotFor(t *testing.T, roots, ips []string) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.RootDomains = roots
	scope.IPs = ips
	scope.Protocols = []string{"tcp"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return rt.base.RoundTrip(req)
}

func TestScanConfirmsAndFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write([]byte("origin-favicon-bytes-stable"))
			return
		}
		w.Write([]byte("<html><head><title>Origin Site</title></head><body>unique origin body content</body></html>"))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)

	nm, err := LoadNetworkMap()
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshotFor(t, []string{"example.com"}, []string{"192.0.2.10"})
	e := New(snap, nil, nm)
	e.client = &http.Client{Transport: rewriteTransport{target: target, base: http.DefaultTransport}}

	ips := []string{"104.16.1.1", "192.0.2.10", "203.0.113.5"}
	res, err := e.Scan(context.Background(), "example.com", ips)
	if err != nil {
		t.Fatal(err)
	}

	foundProtected := false
	for _, p := range res.Protected {
		if p.IP == "104.16.1.1" && p.Provider == "cloudflare" {
			foundProtected = true
		}
	}
	if !foundProtected {
		t.Fatalf("cloudflare IP must be classified as protected: %+v", res.Protected)
	}

	byIP := map[string]OriginCandidate{}
	for _, o := range res.Origins {
		byIP[o.IP] = o
	}
	confirmed, ok := byIP["192.0.2.10"]
	if !ok || confirmed.State != "confirmed" {
		t.Fatalf("in-scope matching IP must be confirmed origin: %+v", confirmed)
	}
	hasBody := false
	for _, r := range confirmed.Reasons {
		if r == "body" {
			hasBody = true
		}
	}
	if !hasBody {
		t.Fatalf("confirmation must include a strong body-hash reason: %+v", confirmed.Reasons)
	}
	blocked, ok := byIP["203.0.113.5"]
	if !ok || !blocked.ScopeBlocked || blocked.Probed {
		t.Fatalf("out-of-scope candidate IP must be blocked and never probed: %+v", blocked)
	}
	if blocked.State != "needsreview" {
		t.Fatalf("blocked candidate must be needsreview, got %q", blocked.State)
	}
}
