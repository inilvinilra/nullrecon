package vulnmatch

import (
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/domain/cve"
	"github.com/nullrecon/nullrecon/domain/technology"
)

func storeMatcher() *StoreMatcher {
	m := NewStoreMatcher()
	m.now = func() time.Time { return time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC) }
	return m
}

func log4jRecord() cve.Record {
	return cve.Record{
		CVE:       "CVE-2021-44228",
		CVSSScore: 10.0,
		Severity:  "critical",
		KEV:       true,
		Products:  []cve.Affected{{Vendor: "apache", Product: "log4j", RangeStartIncl: "2.0", RangeEndExcl: "2.15.0"}},
	}
}

func TestStoreMatchInRange(t *testing.T) {
	m := storeMatcher()
	got := m.Match("proj1", technology.Technology{ID: "t1", AssetID: "a1", Product: "log4j", Version: "2.14.1"}, []cve.Record{log4jRecord()})
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	if got[0].CVE != "CVE-2021-44228" || !got[0].KEV {
		t.Fatalf("bad candidate: %+v", got[0])
	}
}

func TestStoreMatchFixedVersion(t *testing.T) {
	m := storeMatcher()
	if got := m.Match("proj1", technology.Technology{Product: "log4j", Version: "2.15.0"}, []cve.Record{log4jRecord()}); len(got) != 0 {
		t.Fatalf("fixed version must not match, got %d", len(got))
	}
}

func TestStoreMatchExactVersion(t *testing.T) {
	m := storeMatcher()
	rec := cve.Record{CVE: "CVE-2021-41773", CVSSScore: 7.5, Products: []cve.Affected{{Vendor: "apache", Product: "http_server", ExactVersion: "2.4.49"}}}
	if got := m.Match("proj1", technology.Technology{Product: "http_server", Version: "2.4.49"}, []cve.Record{rec}); len(got) != 1 {
		t.Fatalf("exact version must match, got %d", len(got))
	}
	if got := m.Match("proj1", technology.Technology{Product: "http_server", Version: "2.4.50"}, []cve.Record{rec}); len(got) != 0 {
		t.Fatalf("different version must not match exact, got %d", len(got))
	}
}

func TestStoreMatchProductMismatch(t *testing.T) {
	m := storeMatcher()
	if got := m.Match("proj1", technology.Technology{Product: "nginx", Version: "2.14.1"}, []cve.Record{log4jRecord()}); len(got) != 0 {
		t.Fatalf("product mismatch must not match, got %d", len(got))
	}
}

func TestStoreMatchNoVersionNoMatch(t *testing.T) {
	m := storeMatcher()
	if got := m.Match("proj1", technology.Technology{Product: "log4j", Version: ""}, []cve.Record{log4jRecord()}); len(got) != 0 {
		t.Fatalf("missing version must not match, got %d", len(got))
	}
}
