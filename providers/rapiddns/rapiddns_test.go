package rapiddns

import (
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseHTMLTable(t *testing.T) {
	body := []byte(`<table><tr><td>www.cisa.gov</td><td>1.2.3.4</td></tr><tr><td>mail.cisa.gov</td><td>A</td></tr><tr><td>evil.example.com</td><td>x</td></tr><tr><td>www.cisa.gov</td><td>dup</td></tr></table>`)
	page, err := New("").Parse(registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "cisa.gov"}}, registry.Response{Status: 200, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range page.Records {
		got[r.Value] = true
	}
	if !got["www.cisa.gov"] || !got["mail.cisa.gov"] {
		t.Fatalf("expected in-scope hosts, got %v", got)
	}
	if got["evil.example.com"] {
		t.Fatal("out-of-scope host must be filtered")
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 unique in-scope hosts, got %d: %v", len(got), got)
	}
}
