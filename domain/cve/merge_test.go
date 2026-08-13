package cve

import "testing"

func TestMergePreservesKEVAcrossSources(t *testing.T) {
	kevRec := Record{CVE: "CVE-1", KEV: true, KEVDueDate: "2021-12-24", Source: "cisa-kev"}
	nvdRec := Record{CVE: "CVE-1", CVSSScore: 10, Severity: "critical", Source: "nvd", Products: []Affected{{Vendor: "apache", Product: "log4j", RangeEndExcl: "2.15.0"}}}
	merged := Merge(kevRec, nvdRec)
	if !merged.KEV || merged.KEVDueDate != "2021-12-24" {
		t.Fatalf("nvd sync must not clobber KEV flag: %+v", merged)
	}
	if merged.CVSSScore != 10 || len(merged.Products) != 1 {
		t.Fatalf("nvd fields must be applied: %+v", merged)
	}
	if !hasSource(merged.Source, "nvd") || !hasSource(merged.Source, "cisa-kev") {
		t.Fatalf("both sources must be recorded: %q", merged.Source)
	}
}

func TestMergePreservesCVSSWhenIncomingLacksIt(t *testing.T) {
	nvdRec := Record{CVE: "CVE-1", CVSSScore: 9.8, CVSSVector: "v", Severity: "critical", Source: "nvd"}
	kevRec := Record{CVE: "CVE-1", KEV: true, Source: "cisa-kev"}
	merged := Merge(nvdRec, kevRec)
	if merged.CVSSScore != 9.8 || merged.Severity != "critical" {
		t.Fatalf("kev sync must not clear cvss: %+v", merged)
	}
	if !merged.KEV {
		t.Fatalf("kev flag must be set: %+v", merged)
	}
}

func TestMergePreservesEPSS(t *testing.T) {
	withEpss := Record{CVE: "CVE-1", EPSS: 0.97, Source: "epss"}
	nvdRec := Record{CVE: "CVE-1", CVSSScore: 10, Source: "nvd"}
	merged := Merge(withEpss, nvdRec)
	if merged.EPSS != 0.97 {
		t.Fatalf("epss must be preserved: %+v", merged)
	}
}
