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
