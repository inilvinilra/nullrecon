package cvefeed

import (
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestMergeNVDKEVEPSS(t *testing.T) {
	records := []registry.Record{
		{Kind: "cve", Value: "CVE-2021-44228", Fields: map[string]string{
			"cvssScore":  "10",
			"cvssVector": "CVSS:3.1/AV:N",
			"severity":   "critical",
			"cpeRanges":  `[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"2.15.0"}]`,
		}},
		{Kind: "kev", Value: "CVE-2021-44228", Fields: map[string]string{"dueDate": "2021-12-24"}},
		{Kind: "epss", Value: "CVE-2021-44228", Fields: map[string]string{"epss": "0.975"}},
	}
	in := NewIngestor()
	merged := in.Merge(records)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged record, got %d", len(merged))
	}
	r := merged[0]
	if r.CVSSScore != 10 || r.Severity != "critical" {
		t.Fatalf("nvd fields not applied: %+v", r)
	}
	if !r.KEV || r.KEVDueDate != "2021-12-24" {
		t.Fatalf("kev overlay not applied: %+v", r)
	}
	if r.EPSS != 0.975 {
		t.Fatalf("epss overlay not applied: %+v", r)
	}
	if len(r.Products) != 1 {
		t.Fatalf("expected 1 affected product, got %d", len(r.Products))
	}
	p := r.Products[0]
	if p.Vendor != "apache" || p.Product != "log4j" || p.RangeEndExcl != "2.15.0" {
		t.Fatalf("bad affected: %+v", p)
	}
}

func TestExactVersionFromCPE(t *testing.T) {
	records := []registry.Record{
		{Kind: "cve", Value: "CVE-2021-41773", Fields: map[string]string{
			"cvssScore": "7.5",
			"severity":  "high",
			"cpeRanges": `[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]`,
		}},
	}
	merged := NewIngestor().Merge(records)
	if len(merged) != 1 || len(merged[0].Products) != 1 {
		t.Fatalf("expected 1 product, got %+v", merged)
	}
	p := merged[0].Products[0]
	if p.Product != "http_server" || p.ExactVersion != "2.4.49" {
		t.Fatalf("exact version must be extracted from cpe: %+v", p)
	}
}

func TestKEVOnlyRecord(t *testing.T) {
	records := []registry.Record{
		{Kind: "kev", Value: "CVE-2099-0001", Fields: map[string]string{"dueDate": "2099-01-01"}},
	}
	merged := NewIngestor().Merge(records)
	if len(merged) != 1 || !merged[0].KEV || merged[0].Source != "cisa-kev" {
		t.Fatalf("kev-only record must be created: %+v", merged)
	}
}

func TestParseCPEEscaping(t *testing.T) {
	vendor, product, ok := parseCPE(`cpe:2.3:a:vendor\:x:pro\:duct:1.0:*:*:*:*:*:*:*`)
	if !ok {
		t.Fatal("escaped cpe must parse")
	}
	if vendor != "vendor:x" || product != "pro:duct" {
		t.Fatalf("escaped colon must be preserved: vendor=%q product=%q", vendor, product)
	}
}
