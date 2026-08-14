package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reflectionTemplate() *Set {
	set, _ := Parse([]byte(`{"templates":[{
	  "id":"xss-reflect-probe","info":{"name":"Reflected XSS probe","severity":"medium","cve":"CVE-9999-0001","reflection":true},
	  "requests":[{"method":"GET","path":["/search?q=<svg/onload=alert(1)>"],"matchersCondition":"and",
	    "matchers":[{"type":"status","status":[200]},{"type":"word","part":"body","words":["<svg/onload=alert(1)>"]}]}]}]}`))
	return set
}

func TestReflectionConfirmedOnVulnerableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Results for: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, reflectionTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("a genuinely reflecting endpoint must confirm the XSS, got %d matches", len(res.Matches))
	}
}

func TestReflectionNotFiredOnEncodingSoft404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		safe := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(r.URL.String())
		w.Write([]byte("<html><body>Not found: " + safe + " (soft-404)</body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, reflectionTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("an HTML-encoding soft-404 is not vulnerable and must not match, got %d", len(res.Matches))
	}
}

func TestReflectionRejectedWhenMarkerAlwaysPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>This page always contains <svg/onload=alert(1)> as static text.</body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, reflectionTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("a page that always contains the marker (control also matches) must be rejected as FP, got %d", len(res.Matches))
	}
}
