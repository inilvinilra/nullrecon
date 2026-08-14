package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.CIDRs = []string{"127.0.0.0/8"}
	scope.Protocols = []string{"tcp"}
	scope.PortRanges = []scopeguard.PortRange{{Start: 1, End: 65535}}
	scope.ScanClasses = []string{"sqli"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	return New(snap, nil)
}

func target(t *testing.T, srv *httptest.Server, path string) string {
	return srv.URL + path
}

func TestBooleanBasedSQLiConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "1=2") || strings.Contains(id, "'2") || strings.Contains(id, "\"2") {
			w.WriteHeader(500)
			w.Write([]byte("err"))
			return
		}
		w.Write([]byte("<html><body>Forum thread number one with plenty of normal content here.</body></html>"))
	}))
	defer srv.Close()
	res, err := testEngine(t).Scan(context.Background(), target(t, srv, "/showforum?id=1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || !res.Findings[0].Confirmed {
		t.Fatalf("boolean-based SQLi must be confirmed, got %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Type, "boolean-based") {
		t.Fatalf("type must be boolean-based, got %q", res.Findings[0].Type)
	}
}

func TestErrorBasedSQLiConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.HasSuffix(id, "'") {
			w.Write([]byte("Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string"))
			return
		}
		w.Write([]byte("<html>normal</html>"))
	}))
	defer srv.Close()
	res, err := testEngine(t).Scan(context.Background(), target(t, srv, "/p?id=1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Type != "error-based" {
		t.Fatalf("error-based SQLi must be confirmed, got %+v", res.Findings)
	}
}

func TestSafeParamNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>same response regardless of input, parameterized query</html>"))
	}))
	defer srv.Close()
	res, err := testEngine(t).Scan(context.Background(), target(t, srv, "/p?id=1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("safe parameter must not be flagged, got %+v", res.Findings)
	}
}
