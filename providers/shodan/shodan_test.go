package shodan

import (
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseHostFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/shodan/host.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapHostLookup}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("expected 2 services + 1 vulnhint, got %d", len(page.Records))
	}
	ssh := page.Records[0]
	if ssh.Fields["product"] != "OpenSSH" || ssh.Fields["version"] != "9.6" || ssh.Fields["cpe"] != "cpe:/a:openbsd:openssh:9.6" {
		t.Fatalf("bad ssh record: %+v", ssh)
	}
	if ssh.ObservedAt.IsZero() {
		t.Fatal("timestamp must populate observedAt")
	}
	hint := page.Records[2]
	if hint.Kind != "vulnhint" || hint.Fields["vulns"] != "CVE-2023-0000" {
		t.Fatalf("bad vulnhint: %+v", hint)
	}
}

func TestParseSearchPagination(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/shodan/search.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapServiceSearch}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor != "2" {
		t.Fatalf("total 150 implies a second page, got cursor %q", page.NextCursor)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 service records, got %d", len(page.Records))
	}
}

func TestVulnsMapForm(t *testing.T) {
	vulns := parseVulns([]byte(`{"CVE-2024-1111":{"verified":true},"CVE-2024-2222":{}}`))
	if len(vulns) != 2 {
		t.Fatalf("map-form vulns must be extracted, got %v", vulns)
	}
}

func TestBuildHostLookup(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapHostLookup, Params: map[string]string{"ip": "192.0.2.10"}}, "key")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/shodan/host/192.0.2.10" || spec.Query["key"] != "key" {
		t.Fatalf("bad spec: %+v", spec)
	}
}
