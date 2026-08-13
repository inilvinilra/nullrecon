package leakix

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func readFixture(t *testing.T, name string) registry.Response {
	t.Helper()
	data, err := os.ReadFile("../../testdata/providers/leakix/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return registry.Response{Status: 200, Body: data}
}

func TestParseLeakSearch(t *testing.T) {
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapLeakSearch}, readFixture(t, "searchleak.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	rec := page.Records[0]
	if rec.Kind != "leak" || rec.Fields["type"] != "elasticsearch" || rec.Fields["asn"] != "64501" || rec.Fields["datasetRows"] != "1000" {
		t.Fatalf("bad leak record: %+v", rec)
	}
	if rec.ObservedAt.IsZero() {
		t.Fatal("time must populate observedAt")
	}
}

func TestParseHost(t *testing.T) {
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapHostLookup}, readFixture(t, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected service + leak, got %d", len(page.Records))
	}
	if page.Records[1].Kind != "leak" || page.Records[1].Fields["datasetInfected"] != "true" {
		t.Fatalf("bad host leak record: %+v", page.Records[1])
	}
}

func TestParseSubdomains(t *testing.T) {
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapSubdomainSearch}, readFixture(t, "subdomains.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 || page.Records[0].Value != "api.example.com" {
		t.Fatalf("bad subdomains: %+v", page.Records)
	}
}

func TestBuildAuthHeader(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapLeakSearch, Params: map[string]string{"q": "+port:3306"}}, "key")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Headers["api-key"] != "key" || spec.Query["scope"] != "leak" {
		t.Fatalf("bad spec: %+v", spec)
	}
}
