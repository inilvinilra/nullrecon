//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/providers/cisa"
	"github.com/nullrecon/nullrecon/providers/crtsh"
	"github.com/nullrecon/nullrecon/providers/nvd"
	"github.com/nullrecon/nullrecon/providers/registry"
)

func liveFetch(t *testing.T, endpoint string, spec registry.RequestSpec) registry.Response {
	t.Helper()
	u, err := url.Parse(endpoint + spec.Path)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, v := range spec.Query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, spec.Method, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("live network unavailable: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return registry.Response{Status: resp.StatusCode, Body: body}
}

func TestLiveNVDParsesRealCVE(t *testing.T) {
	a := nvd.New("")
	q := registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"cveId": "CVE-2021-44228"}}
	spec, err := a.Build(q, "")
	if err != nil {
		t.Fatal(err)
	}
	resp := liveFetch(t, a.Describe().Endpoint, spec)
	if resp.Status != 200 {
		t.Fatalf("real NVD returned %d", resp.Status)
	}
	page, err := a.Parse(q, resp)
	if err != nil {
		t.Fatalf("parser failed on real NVD response: %v", err)
	}
	if len(page.Records) == 0 || page.Records[0].Value != "CVE-2021-44228" {
		t.Fatalf("expected Log4Shell record from real API, got %+v", page.Records)
	}
	if page.Records[0].Fields["cpeRanges"] == "" {
		t.Fatal("real Log4Shell record must carry cpe ranges; parser or field mapping is wrong")
	}
	if page.Records[0].Fields["cvssScore"] == "" {
		t.Fatal("real record must carry a cvss score")
	}
}

func TestLiveCISAKEVParsesCatalog(t *testing.T) {
	a := cisa.New("")
	q := registry.Query{Capability: registry.CapExploitPriority}
	spec, err := a.Build(q, "")
	if err != nil {
		t.Fatal(err)
	}
	resp := liveFetch(t, a.Describe().Endpoint, spec)
	if resp.Status != 200 {
		t.Fatalf("real CISA returned %d", resp.Status)
	}
	page, err := a.Parse(q, resp)
	if err != nil {
		t.Fatalf("parser failed on real KEV catalog: %v", err)
	}
	if len(page.Records) < 500 {
		t.Fatalf("real KEV catalog should have >500 entries, parser yielded %d", len(page.Records))
	}
	for _, rec := range page.Records {
		if rec.Value == "" || rec.Fields["kev"] != "true" {
			t.Fatalf("malformed kev record from real feed: %+v", rec)
		}
	}
}

func TestLiveCrtShParsesSubdomains(t *testing.T) {
	a := crtsh.New("")
	q := registry.Query{Capability: registry.CapSubdomainSearch, Params: map[string]string{"domain": "example.com"}}
	spec, err := a.Build(q, "")
	if err != nil {
		t.Fatal(err)
	}
	resp := liveFetch(t, a.Describe().Endpoint, spec)
	if resp.Status != 200 {
		t.Fatalf("real crt.sh returned %d", resp.Status)
	}
	page, err := a.Parse(q, resp)
	if err != nil {
		t.Fatalf("parser failed on real crt.sh response: %v", err)
	}
	if len(page.Records) == 0 {
		t.Fatal("real crt.sh should return certificate names for example.com")
	}
}
