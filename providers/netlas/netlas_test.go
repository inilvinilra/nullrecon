package netlas

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/netlas/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapServiceSearch}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(page.Records))
	}
	if page.NextCursor != "2" {
		t.Fatalf("offset pagination must advance by items consumed, got %q", page.NextCursor)
	}
	first := page.Records[0]
	if first.Value != "192.0.2.10" || first.Fields["host"] != "www.example.com" || first.Fields["port"] != "443" {
		t.Fatalf("bad record: %+v", first)
	}
}

func TestBuildOffsetAndAuth(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapServiceSearch, Params: map[string]string{"q": "port:7001"}, Cursor: "40"}, "key")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/api/responses/" || spec.Query["start"] != "40" || spec.Headers["X-API-Key"] != "key" {
		t.Fatalf("bad spec: %+v", spec)
	}
	if _, err := a.Build(registry.Query{Capability: registry.CapServiceSearch, Params: map[string]string{"q": "x"}, Cursor: "bogus"}, "key"); err == nil {
		t.Fatal("invalid cursor must fail")
	}
}

func TestLastPageHasNoCursor(t *testing.T) {
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapServiceSearch, Cursor: "380"}, registry.Response{Status: 200, Body: []byte(`{"items":[],"total":40}`)})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor != "" {
		t.Fatal("exhausted result set must not emit a cursor")
	}
}
