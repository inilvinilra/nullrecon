package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func testSnapshot(t *testing.T, host string, port int) scopeguard.Snapshot {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.IPs = []string{host}
	scope.Ports = []int{port}
	scope.Protocols = []string{"tcp"}
	scope.ScanClasses = []string{"vulntemplate"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

func TestEngineMatchesGitConfigAndExtracts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/a/b.git\n"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	engine := New(testSnapshot(t, host, port), nil)
	res, err := engine.Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	var git *Match
	for i := range res.Matches {
		if res.Matches[i].TemplateID == "git-config-exposure" {
			git = &res.Matches[i]
		}
	}
	if git == nil {
		t.Fatalf("expected git-config match, got %+v", res.Matches)
	}
	if git.Severity != "high" {
		t.Fatalf("expected high severity, got %q", git.Severity)
	}
	remotes := git.Extracted["remote"]
	if len(remotes) != 1 || remotes[0] != "https://example.com/a/b.git" {
		t.Fatalf("extractor must capture remote url, got %v", remotes)
	}
}

func TestEngineHeaderMatcherAndExtractor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	engine := New(testSnapshot(t, host, port), nil)
	res, err := engine.Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	var found *Match
	for i := range res.Matches {
		if res.Matches[i].TemplateID == "server-version-disclosure" {
			found = &res.Matches[i]
		}
	}
	if found == nil {
		t.Fatalf("expected server-version match, got %+v", res.Matches)
	}
	if got := found.Extracted["server"]; len(got) == 0 || got[0] != "nginx/1.18.0" {
		t.Fatalf("expected extracted server header, got %v", got)
	}
}

func TestEngineNoMatchOnCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, _ := LoadEmbedded()
	engine := New(testSnapshot(t, host, port), nil)
	res, err := engine.Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Matches {
		if m.TemplateID != "server-version-disclosure" {
			t.Fatalf("clean 404 server must not match %q", m.TemplateID)
		}
	}
}

func TestEngineScopeGatesOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]\nrepositoryformatversion = 0\n"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	snap := testSnapshot(t, host, port+1)
	set, _ := LoadEmbedded()
	engine := New(snap, nil)
	res, err := engine.Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	if res.Requested != 0 || res.Blocked == 0 {
		t.Fatalf("out-of-scope port must be blocked, not requested: requested=%d blocked=%d", res.Requested, res.Blocked)
	}
}
