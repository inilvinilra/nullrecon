package crtsh

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseCrtShFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/crtsh/search.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapSubdomainSearch}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range page.Records {
		if r.Kind != "hostname" {
			t.Fatalf("expected hostname record, got %q", r.Kind)
		}
		names[r.Value] = true
	}
	for _, want := range []string{"www.example.com", "example.com", "api.example.com"} {
		if !names[want] {
			t.Fatalf("expected %q in results, got %v", want, names)
		}
	}
	if len(page.Records) != 3 {
		t.Fatalf("wildcard and duplicate names must be deduped to 3 unique hosts, got %d: %v", len(page.Records), names)
	}
	for n := range names {
		if n[0] == '*' {
			t.Fatalf("wildcard prefix must be stripped: %q", n)
		}
	}
}

func TestBuildCrtSh(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "example.com"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["q"] != "%.example.com" || spec.Query["output"] != "json" {
		t.Fatalf("bad query: %+v", spec.Query)
	}
}
