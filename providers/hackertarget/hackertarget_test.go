package hackertarget

import (
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseHostsearchCSV(t *testing.T) {
	body := []byte("www.example.com,1.2.3.4\napi.example.com,1.2.3.5\nwww.example.com,1.2.3.4\n")
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapSubdomainSearch}, registry.Response{Status: 200, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range page.Records {
		if r.Kind != "hostname" {
			t.Fatalf("expected hostname record, got %q", r.Kind)
		}
		got[r.Value] = r.Fields["address"]
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 unique hosts (deduped), got %d: %v", len(got), got)
	}
	if got["www.example.com"] != "1.2.3.4" {
		t.Fatalf("address not captured: %v", got)
	}
}

func TestParseRateLimitIsError(t *testing.T) {
	a := New("")
	_, err := a.Parse(registry.Query{Capability: registry.CapSubdomainSearch}, registry.Response{Status: 200, Body: []byte("API count exceeded - Increase Quota with Membership")})
	if err == nil {
		t.Fatal("rate-limit body must surface as an error so the aggregator records it")
	}
}

func TestBuildRequiresDomain(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{}}, ""); err == nil {
		t.Fatal("missing domain must error")
	}
	spec, err := a.Build(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "example.com"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["q"] != "example.com" {
		t.Fatalf("unexpected query %v", spec.Query)
	}
}
