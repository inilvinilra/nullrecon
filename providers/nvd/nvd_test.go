package nvd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestParseCVEFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/providers/nvd/cves.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New("")
	page, err := a.Parse(registry.Query{Capability: registry.CapCVELookup}, registry.Response{Status: 200, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 CVE records, got %d", len(page.Records))
	}
	if page.NextCursor != "2" {
		t.Fatalf("startIndex 0 + resultsPerPage 2 < total 3 implies next cursor 2, got %q", page.NextCursor)
	}
	log4j := page.Records[0]
	if log4j.Value != "CVE-2021-44228" {
		t.Fatalf("bad cve id: %q", log4j.Value)
	}
	if log4j.Fields["cvssScore"] != "10" || log4j.Fields["severity"] != "critical" {
		t.Fatalf("bad cvss fields: %+v", log4j.Fields)
	}
	if log4j.Fields["description"] == "" || log4j.Fields["description"][0:6] != "Apache" {
		t.Fatalf("english description must be chosen: %q", log4j.Fields["description"])
	}
	var ranges []cpeMatch
	if err := json.Unmarshal([]byte(log4j.Fields["cpeRanges"]), &ranges); err != nil {
		t.Fatalf("cpeRanges must be valid json: %v", err)
	}
	if len(ranges) != 1 || ranges[0].VersionEndExcluding != "2.15.0" {
		t.Fatalf("bad cpe range: %+v", ranges)
	}
	if ranges[0].Criteria != "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*" {
		t.Fatalf("bad cpe criteria: %q", ranges[0].Criteria)
	}
}

func TestBuildByCVEID(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"cveId": "CVE-2021-44228"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != "/rest/json/cves/2.0" || spec.Query["cveId"] != "CVE-2021-44228" {
		t.Fatalf("bad spec: %+v", spec)
	}
	if _, ok := spec.Headers["apiKey"]; ok {
		t.Fatal("no api key header must be set when secret is empty")
	}
}

func TestBuildWithKeyAndCursor(t *testing.T) {
	a := New("")
	spec, err := a.Build(registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{"keyword": "log4j"}, Cursor: "2000"}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Query["keywordSearch"] != "log4j" || spec.Query["startIndex"] != "2000" {
		t.Fatalf("bad query: %+v", spec.Query)
	}
	if spec.Headers["apiKey"] != "secret" {
		t.Fatalf("api key header must be set: %+v", spec.Headers)
	}
}

func TestBuildRequiresParam(t *testing.T) {
	a := New("")
	if _, err := a.Build(registry.Query{Capability: registry.CapCVELookup, Params: map[string]string{}}, ""); err == nil {
		t.Fatal("expected error when no search param is supplied")
	}
}

func TestParseFeedFormat(t *testing.T) {
	feed := `{"cve_count":2,"feed_name":"CVE-2022","cve_items":[
	  {"id":"CVE-2022-0001","published":"2022-01-01T00:00:00.000","lastModified":"2022-02-01T00:00:00.000","vulnStatus":"Analyzed",
	   "descriptions":[{"lang":"en","value":"desc"}],
	   "metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
	   "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0.0"}]}]}]},
	  {"id":"CVE-2022-0002","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"rejected"}]}
	]}`
	records, err := ParseFeed([]byte(feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("ParseFeed must yield a record per cve_item, got %d", len(records))
	}
	first := records[0]
	if first.Value != "CVE-2022-0001" || first.Fields["cvssScore"] != "9.8" {
		t.Fatalf("bad first record: %+v", first.Fields)
	}
	if first.Fields["cpeRanges"] == "" {
		t.Fatal("feed record must carry cpe ranges")
	}
	if records[1].Fields["status"] != "Rejected" {
		t.Fatalf("status must be preserved for downstream filtering: %+v", records[1].Fields)
	}
}
