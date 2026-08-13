package censys

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/censys/hostssearch.json")
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
	if page.NextCursor != "cursor-token-2" {
		t.Fatalf("cursor must propagate, got %q", page.NextCursor)
	}
	first := page.Records[0]
	if first.Value != "192.0.2.10" || first.Fields["asn"] != "64500" {
		t.Fatalf("bad record: %+v", first)
	}
	if first.Fields["services"] != "443/HTTPS,80/HTTP" {
		t.Fatalf("bad services field: %q", first.Fields["services"])
	}
}

func TestBuildCursor(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapServiceSearch, Params: map[string]string{"q": "x"}, Cursor: "abc"}, "token")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["cursor"] != "abc" || spec.Headers["Authorization"] != "Bearer token" {
		t.Fatalf("bad spec: %+v", spec)
	}
}

func TestParseErrorStatus(t *testing.T) {
	a := New("")
	_, err := a.Parse(registry.Query{}, registry.Response{Status: 403, Body: []byte(`{"code":403,"status":"Forbidden"}`)})
	if err == nil {
		t.Fatal("error status must fail parse")
	}
}
