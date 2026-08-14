package contentdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPathReflectingSoft404NoCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<!doctype html><html><head><title>Page Not Found</title></head><body><h1>Oops</h1>" +
			"<p>The page <b>" + r.URL.Path + "</b> could not be located on this server. Please check the URL and try again.</p>" +
			"<a href=\"/\">home</a></body></html>"))
	}))
	defer srv.Close()
	snap := snapshotForHost(t, hostOf(t, srv))
	e := New(snap, nil)
	opt := Options{Words: []string{"admin", "login", "config", "backup", "old", "test", "api", "phpinfo.php", "wp-admin", ".git", "server-status", "secret"}}
	res, err := e.Scan(context.Background(), srv.URL, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Baseline.CatchAll {
		t.Fatalf("a path-reflecting soft-404 must be detected as catch-all: %+v", res.Baseline)
	}
	var candidates int
	for _, h := range res.Hits {
		if h.Class == "candidate" {
			candidates++
		}
	}
	if candidates != 0 {
		t.Fatalf("path-reflecting soft-404 (every path unique) must yield ZERO candidates, got %d", candidates)
	}
}

func TestPathReflectingCatchAllStillFindsRealPaths(t *testing.T) {
	real := map[string]string{
		"/admin":  "<html><head><title>Admin Panel</title></head><body><h1>Administration Control Panel</h1><form id='adminlogin'><input name='u'><input name='p'><button>Sign in to dashboard</button></form></body></html>",
		"/backup": "<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><pre><a href='database.sql'>database.sql</a> 4.2M\n<a href='site.tar.gz'>site.tar.gz</a> 88M</pre></body></html>",
		"/api":    `{"name":"acme-api","version":"1.4.2","status":"operational","endpoints":["/api/v1/users","/api/v1/orders"]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := real[r.URL.Path]; ok {
			w.WriteHeader(200)
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<!doctype html><html><head><title>Acme Store</title></head><body>" +
			"<h1>Welcome to Acme Store</h1><p>The resource " + r.URL.Path +
			" is part of our catalog. Browse featured products below.</p>" +
			"<nav>Home About Products Contact Support</nav></body></html>"))
	}))
	defer srv.Close()
	snap := snapshotForHost(t, hostOf(t, srv))
	e := New(snap, nil)
	opt := Options{Words: []string{
		"admin", "backup", "api",
		"dashboard", "config", "wp-admin", "uploads", "images", "css", "js",
		"test", "old", "dev", "staging", "private", "secret", "data", "files", "docs", "assets",
	}}
	res, err := e.Scan(context.Background(), srv.URL, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Baseline.CatchAll {
		t.Fatalf("a 200 path-reflecting catch-all must be detected: %+v", res.Baseline)
	}
	found := map[string]bool{}
	for _, h := range res.Hits {
		if h.Class == "candidate" {
			found[h.Path] = true
		}
	}
	for _, want := range []string{"admin", "backup", "api"} {
		if !found[want] {
			t.Fatalf("real distinct path %q must be recovered from a catch-all baseline: found=%v", want, found)
		}
	}
	if len(found) != 3 {
		t.Fatalf("exactly the 3 real paths must be candidates, got %d: %v", len(found), found)
	}
}
