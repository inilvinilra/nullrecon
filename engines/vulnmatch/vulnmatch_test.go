package vulnmatch

import (
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/domain/technology"
)

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	set, err := LoadRules()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	e := New(set)
	e.now = func() time.Time { return time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC) }
	return e
}

func techFor(product, version string) technology.Technology {
	return technology.Technology{ID: "tech1", AssetID: "asset1", Product: product, Version: version}
}

func TestVulnerableVersionMatches(t *testing.T) {
	e := loadEngine(t)
	got := e.Match("proj1", techFor("log4j", "2.14.1"))
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	c := got[0]
	if c.CVE != "CVE-2021-44228" {
		t.Fatalf("expected Log4Shell CVE, got %q", c.CVE)
	}
	if !c.KEV {
		t.Fatalf("expected KEV flag set")
	}
	if c.CVSS == nil || c.CVSS.Score != 10.0 {
		t.Fatalf("expected CVSS 10.0, got %+v", c.CVSS)
	}
	if c.VersionEvidence != "2.14.1" {
		t.Fatalf("expected version evidence, got %q", c.VersionEvidence)
	}
}

func TestFixedVersionDoesNotMatch(t *testing.T) {
	e := loadEngine(t)
	if got := e.Match("proj1", techFor("log4j", "2.15.0")); len(got) != 0 {
		t.Fatalf("expected no candidates for fixed version, got %d", len(got))
	}
	if got := e.Match("proj1", techFor("log4j", "2.17.1")); len(got) != 0 {
		t.Fatalf("expected no candidates for patched version, got %d", len(got))
	}
}

func TestMissingVersionYieldsNoMatch(t *testing.T) {
	e := loadEngine(t)
	if got := e.Match("proj1", techFor("log4j", "")); len(got) != 0 {
		t.Fatalf("expected no candidates without a concrete version, got %d", len(got))
	}
	if got := e.Match("proj1", techFor("log4j", "unknown")); len(got) != 0 {
		t.Fatalf("expected no candidates for unparseable version, got %d", len(got))
	}
}

func TestExactVersionConstraint(t *testing.T) {
	e := loadEngine(t)
	if got := e.Match("proj1", techFor("httpd", "2.4.49")); len(got) != 1 {
		t.Fatalf("expected match for httpd 2.4.49, got %d", len(got))
	}
	if got := e.Match("proj1", techFor("httpd", "2.4.50")); len(got) != 0 {
		t.Fatalf("expected no match for httpd 2.4.50, got %d", len(got))
	}
}

func TestMultiRangeConstraint(t *testing.T) {
	e := loadEngine(t)
	if got := e.Match("proj1", techFor("php", "7.2.10")); len(got) != 1 {
		t.Fatalf("expected match for php 7.2.10, got %d", len(got))
	}
	if got := e.Match("proj1", techFor("php", "7.2.24")); len(got) != 0 {
		t.Fatalf("expected no match for php 7.2.24 (fixed), got %d", len(got))
	}
	if got := e.Match("proj1", techFor("php", "8.1.0")); len(got) != 0 {
		t.Fatalf("expected no match for php 8.1.0, got %d", len(got))
	}
}

func TestVendorMismatchSkips(t *testing.T) {
	e := loadEngine(t)
	tech := techFor("log4j", "2.14.1")
	tech.Vendor = "acme"
	if got := e.Match("proj1", tech); len(got) != 0 {
		t.Fatalf("expected no match on vendor mismatch, got %d", len(got))
	}
}

func TestUnknownProductNoMatch(t *testing.T) {
	e := loadEngine(t)
	if got := e.Match("proj1", techFor("customserver", "1.0.0")); len(got) != 0 {
		t.Fatalf("expected no candidates for unknown product, got %d", len(got))
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.0", "1.10.0", -1},
		{"2.4.50", "2.4.49", 1},
		{"1.0.1", "1.0.1g", -1},
		{"1.0.1f", "1.0.1g", -1},
		{"2.5.10.1", "2.5.10", 1},
	}
	for _, tc := range cases {
		a, b := parseVersion(tc.a), parseVersion(tc.b)
		if got := compareVersions(a, b); got != tc.want {
			t.Fatalf("compare(%s,%s)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
