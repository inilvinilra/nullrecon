package exposure

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
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

func snapshotForHost(t *testing.T, host string, customize ...func(*scopeguard.Scope)) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
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

func hostOf(t *testing.T, url string) string {
	t.Helper()
	return strings.Split(strings.TrimPrefix(url, "http://"), ":")[0]
}

func exposureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/x/y.git\n"))
		case "/.env":
			w.Write([]byte("APP_ENV=production\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nDB_PASSWORD=sup3rs3cr3tvalue\n"))
		case "/phpinfo.php":
			w.Write([]byte("<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.2</body></html>"))
		default:
			w.Write([]byte("<html><body>not found</body></html>"))
		}
	}))
}

func TestScanConfirmsExposuresAndSuppressesFalsePositives(t *testing.T) {
	srv := exposureServer()
	defer srv.Close()
	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	red, _ := redaction.New(nil)
	snap := snapshotForHost(t, hostOf(t, srv.URL))
	e := New(snap, nil, red, set)
	res, err := e.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]Finding{}
	for _, f := range res.Findings {
		byID[f.SignatureID] = f
	}
	if _, ok := byID["git-config"]; !ok {
		t.Fatalf("exposed .git/config must be confirmed: %+v", res.Findings)
	}
	if byID["git-config"].Severity != "high" || byID["git-config"].State != "confirmed" {
		t.Fatalf("git-config finding wrong: %+v", byID["git-config"])
	}
	env, ok := byID["env-file"]
	if !ok {
		t.Fatalf("exposed .env must be confirmed: %+v", res.Findings)
	}
	if env.EvidencePreview != "" {
		t.Fatalf("leak-category finding must not include a raw preview: %q", env.EvidencePreview)
	}
	php, ok := byID["phpinfo"]
	if !ok {
		t.Fatal("phpinfo must be confirmed")
	}
	if php.EvidencePreview == "" {
		t.Fatal("non-leak exposure should carry a redacted preview")
	}
	if strings.Contains(php.EvidencePreview, "sup3rs3cr3tvalue") {
		t.Fatal("preview must never contain secret material")
	}
	for _, noise := range []string{"server-status", "sql-dump", "swagger", "npmrc", "ds-store", "directory-listing"} {
		if _, ok := byID[noise]; ok {
			t.Fatalf("signature %q must not fire on a soft-404 html body", noise)
		}
	}
}

func TestScanRespectsBudgetAndScope(t *testing.T) {
	srv := exposureServer()
	defer srv.Close()
	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	budget := budgetguard.New("test", budgetguard.Budget{budgetguard.DimRequests: 3}, nil)
	snap := snapshotForHost(t, hostOf(t, srv.URL), func(s *scopeguard.Scope) {
		s.DeniedPaths = []string{"/.git"}
	})
	e := New(snap, budget, nil, set)
	res, err := e.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.Requested > 3 {
		t.Fatalf("request budget of 3 must be respected, made %d", res.Requested)
	}
	if res.Blocked == 0 {
		t.Fatalf("denied path and budget exhaustion must block requests: %+v", res)
	}
	for _, f := range res.Findings {
		if f.SignatureID == "git-config" {
			t.Fatal("denied .git path must never be requested")
		}
	}
}
