package certspotter

import (
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseIssuances(t *testing.T) {
	body := []byte(`[{"dns_names":["*.ci.protectivedns.cisa.gov","ci.protectivedns.cisa.gov"]},{"dns_names":["www.cisa.gov","www.cisa.gov"]}]`)
	page, err := New("").Parse(registry.Query{Capability: registry.CapSubdomainSearch}, registry.Response{Status: 200, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range page.Records {
		got[r.Value] = true
	}
	for _, want := range []string{"ci.protectivedns.cisa.gov", "www.cisa.gov"} {
		if !got[want] {
			t.Fatalf("expected %q, got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 unique deduped hosts, got %d: %v", len(got), got)
	}
}

func TestBuildQuery(t *testing.T) {
	spec, err := New("").Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "cisa.gov"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["include_subdomains"] != "true" || spec.Query["domain"] != "cisa.gov" {
		t.Fatalf("unexpected query %v", spec.Query)
	}
}
