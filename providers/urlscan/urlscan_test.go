package urlscan

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseURLScanFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/urlscan/search.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapURLHistory}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	var host, url bool
	for _, r := range page.Records {
		if r.Kind == "hostname" && r.Value == "www.example.com" && r.Fields["ip"] == "93.184.216.34" {
			host = true
		}
		if r.Kind == "url" && r.Value == "https://www.example.com/login" {
			url = true
		}
	}
	if !host || !url {
		t.Fatalf("expected both hostname and url records, got %+v", page.Records)
	}
}

func TestBuildURLScanOptionalAuth(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapURLHistory, Params: map[string]string{"domain": "example.com"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["q"] != "domain:example.com" {
		t.Fatalf("bad query: %+v", spec.Query)
	}
	if _, ok := spec.Headers["API-Key"]; ok {
		t.Fatal("no key header when secret empty")
	}
	spec, _ = a.Build(registry.Query{Capability: registry.CapURLHistory, Params: map[string]string{"domain": "example.com"}}, "k")
	if spec.Headers["API-Key"] != "k" {
		t.Fatal("key header must be set when secret present")
	}
}
