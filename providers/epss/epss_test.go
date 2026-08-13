package epss

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseEPSSFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/epss/epss.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapExploitPriority}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 epss record, got %d", len(page.Records))
	}
	r := page.Records[0]
	if r.Kind != "epss" || r.Value != "CVE-2021-44228" || r.Fields["epss"] != "0.97565" {
		t.Fatalf("bad epss record: %+v", r)
	}
}

func TestBuildRequiresCVE(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapExploitPriority, Params: map[string]string{}}, ""); err == nil {
		t.Fatal("expected error without cve param")
	}
	spec, err := a.Build(registry.Query{Capability: registry.CapExploitPriority, Params: map[string]string{"cve": "CVE-2021-44228"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["cve"] != "CVE-2021-44228" || spec.Path != "/data/v1/epss" {
		t.Fatalf("bad spec: %+v", spec)
	}
}
