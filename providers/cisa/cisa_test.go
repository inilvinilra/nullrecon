package cisa

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseKEVFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/cisa/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapExploitPriority}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 kev records, got %d", len(page.Records))
	}
	log4j := page.Records[0]
	if log4j.Kind != "kev" || log4j.Value != "CVE-2021-44228" {
		t.Fatalf("bad kev record: %+v", log4j)
	}
	if log4j.Fields["kev"] != "true" || log4j.Fields["dueDate"] != "2021-12-24" {
		t.Fatalf("bad kev fields: %+v", log4j.Fields)
	}
	if log4j.Fields["ransomware"] != "Known" {
		t.Fatalf("ransomware flag must populate: %+v", log4j.Fields)
	}
}

func TestBuildKEV(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapExploitPriority}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/sites/default/files/feeds/known_exploited_vulnerabilities.json" {
		t.Fatalf("bad path: %q", spec.Path)
	}
}
