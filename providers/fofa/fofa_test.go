package fofa

import (
	"os"
	"strings"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func fixture(t *testing.T, name string) registry.Response {
	t.Helper()
	data, err := os.ReadFile("../../testdata/providers/fofa/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return registry.Response{Status: 200, Body: data}
}

func TestDescriptor(t *testing.T) {
	a := New("")
	d := a.Describe()
	if d.Name != "fofa" || !d.Supports(registry.CapAssetSearch) {
		t.Fatalf("bad descriptor: %+v", d)
	}
}

func TestBuildRequiresCredential(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapAssetSearch, Params: map[string]string{"q": "host=\"example.com\""}}, ""); err == nil {
		t.Fatal("missing credential must fail")
	}
	if _, err := a.Build(registry.Query{Capability: registry.CapAssetSearch, Params: map[string]string{"q": "x"}}, "no-colon"); err == nil {
		t.Fatal("credential without email:key shape must fail")
	}
	spec, err := a.Build(registry.Query{Capability: registry.CapAssetSearch, Params: map[string]string{"q": "host=\"example.com\""}}, "user@example.com:secretkey")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/api/v1/search/all" || spec.Query["email"] != "user@example.com" || spec.Query["key"] != "secretkey" {
		t.Fatalf("bad request spec: %+v", spec)
	}
}

func TestParseFixture(t *testing.T) {
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapAssetSearch}, fixture(t, "search.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(page.Records))
	}
	first := page.Records[0]
	if first.Value != "192.0.2.10" || first.Fields["host"] != "www.example.com" || first.Fields["server"] != "nginx" {
		t.Fatalf("bad first record: %+v", first)
	}
	second := page.Records[1]
	if second.ObservedAt.IsZero() {
		t.Fatal("lastupdatetime must populate observedAt")
	}
}

func TestParseAPIError(t *testing.T) {
	a := New("")
	_, err := a.Parse(registry.Query{}, registry.Response{Status: 200, Body: []byte(`{"error":true,"errmsg":"invalid key"}`)})
	if err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Fatalf("api error must surface: %v", err)
	}
}

func TestParseTruncatedRejected(t *testing.T) {
	a := New("")
	if _, err := a.Parse(registry.Query{}, registry.Response{Status: 200, Body: []byte(`{"error":false,"results":[`)}); err == nil {
		t.Fatal("truncated payload must be rejected")
	}
}
