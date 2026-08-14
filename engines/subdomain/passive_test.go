package subdomain

import (
	"context"
	"errors"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

type mockEnum struct {
	byName map[string]registry.Result
	errs   map[string]error
}

func (m mockEnum) Execute(_ context.Context, name string, _ registry.Query) (registry.Result, error) {
	if err, ok := m.errs[name]; ok {
		return registry.Result{}, err
	}
	return m.byName[name], nil
}

func recs(hosts ...string) registry.Result {
	var r registry.Result
	for _, h := range hosts {
		r.Records = append(r.Records, registry.Record{Kind: "hostname", Value: h})
	}
	return r
}

func TestEnumeratePassiveMergesDedupsAndScopes(t *testing.T) {
	m := mockEnum{
		byName: map[string]registry.Result{
			"crtsh":   recs("www.cisa.gov", "us-cert.cisa.gov", "*.cisa.gov"),
			"urlscan": recs("us-cert.cisa.gov", "sso.cisa.gov", "evil.example.com"),
			"leakix":  recs("mail.cisa.gov"),
		},
		errs: map[string]error{
			"virustotal": errors.New("auth missing"),
		},
	}
	res := EnumeratePassive(context.Background(), m, []string{"crtsh", "urlscan", "leakix", "virustotal"}, "cisa.gov")

	want := []string{"mail.cisa.gov", "sso.cisa.gov", "us-cert.cisa.gov", "www.cisa.gov"}
	if len(res.Hostnames) != len(want) {
		t.Fatalf("expected %d unique in-scope hostnames, got %d: %v", len(want), len(res.Hostnames), res.Hostnames)
	}
	for i := range want {
		if res.Hostnames[i] != want[i] {
			t.Fatalf("hostname %d = %q, want %q (full: %v)", i, res.Hostnames[i], want[i], res.Hostnames)
		}
	}
	for _, h := range res.Hostnames {
		if h == "evil.example.com" {
			t.Fatal("out-of-scope host must be filtered")
		}
	}
	if res.Errors["virustotal"] == "" {
		t.Fatal("failed source must be recorded, not fatal")
	}
	if res.BySource["crtsh"] != 2 {
		t.Fatalf("crtsh in-scope contributions expected 2 (apex wildcard dropped), got %d", res.BySource["crtsh"])
	}
}

func TestEnumeratePassiveAllSourcesDownReturnsEmpty(t *testing.T) {
	m := mockEnum{errs: map[string]error{"crtsh": errors.New("503"), "urlscan": errors.New("429")}}
	res := EnumeratePassive(context.Background(), m, []string{"crtsh", "urlscan"}, "cisa.gov")
	if len(res.Hostnames) != 0 {
		t.Fatalf("expected empty result when all sources fail, got %v", res.Hostnames)
	}
	if len(res.Errors) != 2 {
		t.Fatalf("both source failures must be recorded, got %v", res.Errors)
	}
}
