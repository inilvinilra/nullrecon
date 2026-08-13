package virustotal

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseSubdomainsFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/virustotal/subdomains.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapSubdomainSearch}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 subdomains, got %d", len(page.Records))
	}
	if page.Records[1].Value != "mail.example.com" {
		t.Fatalf("hostname must be lowercased, got %q", page.Records[1].Value)
	}
	if page.NextCursor != "NEXTCUR" {
		t.Fatalf("cursor pagination must carry meta cursor, got %q", page.NextCursor)
	}
}

func TestBuildRequiresKey(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "example.com"}}, ""); err != registry.ErrAuthMissing {
		t.Fatalf("expected ErrAuthMissing, got %v", err)
	}
	spec, err := a.Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "example.com"}}, "k")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/api/v3/domains/example.com/subdomains" || spec.Headers["x-apikey"] != "k" {
		t.Fatalf("bad spec: %+v", spec)
	}
}
