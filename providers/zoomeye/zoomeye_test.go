package zoomeye

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseZoomEyeFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/zoomeye/search.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapServiceSearch}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 service records, got %d", len(page.Records))
	}
	https := page.Records[0]
	if https.Fields["product"] != "nginx" || https.Fields["version"] != "1.18.0" || https.Fields["port"] != "443" {
		t.Fatalf("bad service record: %+v", https.Fields)
	}
	if page.NextCursor != "2" {
		t.Fatalf("total 42 > page 20 implies next cursor 2, got %q", page.NextCursor)
	}
}

func TestBuildRequiresKey(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapServiceSearch, Params: map[string]string{"q": "nginx"}}, ""); err != registry.ErrAuthMissing {
		t.Fatalf("expected ErrAuthMissing, got %v", err)
	}
	spec, err := a.Build(registry.Query{Capability: registry.CapHostLookup, Params: map[string]string{"ip": "1.2.3.4"}}, "k")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["query"] != "ip:1.2.3.4" || spec.Headers["API-KEY"] != "k" {
		t.Fatalf("bad spec: %+v", spec)
	}
}
