package vulnmatch

import (
	"testing"

	"github.com/nullrecon/nullrecon/domain/cve"
	"github.com/nullrecon/nullrecon/domain/technology"
)

func TestStoreMatchExchangeBuildNormalization(t *testing.T) {
	m := storeMatcher()
	proxyLogon := cve.Record{
		CVE:       "CVE-2021-26855",
		CVSSScore: 9.8,
		KEV:       true,
		Products: []cve.Affected{
			{Vendor: "microsoft", Product: "exchange_server", ExactVersion: "2013"},
			{Vendor: "microsoft", Product: "exchange_server", ExactVersion: "2016"},
			{Vendor: "microsoft", Product: "exchange_server", ExactVersion: "2019"},
		},
	}
	exchange := func(v string) technology.Technology {
		return technology.Technology{Product: "exchange_server", Vendor: "microsoft", Version: v}
	}
	if got := m.Match("p", exchange("15.1.2507.6"), []cve.Record{proxyLogon}); len(got) != 1 {
		t.Fatalf("Exchange 2016 build (15.1.x) must map to a ProxyLogon match, got %d", len(got))
	}
	if got := m.Match("p", exchange("15.0.1497"), []cve.Record{proxyLogon}); len(got) != 1 {
		t.Fatalf("Exchange 2013 build (15.0.x) must map to a match, got %d", len(got))
	}
	if got := m.Match("p", exchange("15.2.1118"), []cve.Record{proxyLogon}); len(got) != 1 {
		t.Fatalf("Exchange 2019 build (15.2.x) must map to a match, got %d", len(got))
	}

	only2016 := cve.Record{CVE: "CVE-TEST-2016", Products: []cve.Affected{{Vendor: "microsoft", Product: "exchange_server", ExactVersion: "2016"}}}
	if got := m.Match("p", exchange("15.0.1497"), []cve.Record{only2016}); len(got) != 0 {
		t.Fatalf("a 2013 build must not match a 2016-only record, got %d", len(got))
	}

	notExchange := cve.Record{CVE: "CVE-X", Products: []cve.Affected{{Product: "http_server", ExactVersion: "2016"}}}
	if got := m.Match("p", technology.Technology{Product: "http_server", Version: "15.1.2507"}, []cve.Record{notExchange}); len(got) != 0 {
		t.Fatalf("normalization must only apply to exchange_server, got %d", len(got))
	}
}

func TestStoreMatchSharePointBuildNormalization(t *testing.T) {
	m := storeMatcher()
	sp := func(v string) technology.Technology {
		return technology.Technology{Product: "sharepoint_server", Vendor: "microsoft", Version: v}
	}
	cal2019 := cve.Record{CVE: "CVE-2023-29357", Products: []cve.Affected{{Vendor: "microsoft", Product: "sharepoint_server", ExactVersion: "2019"}}}
	cal2016 := cve.Record{CVE: "CVE-SP-2016", Products: []cve.Affected{{Vendor: "microsoft", Product: "sharepoint_server", ExactVersion: "2016"}}}
	cal2013 := cve.Record{CVE: "CVE-SP-2013", Products: []cve.Affected{{Vendor: "microsoft", Product: "sharepoint_server", ExactVersion: "2013"}}}
	buildRange := cve.Record{CVE: "CVE-SP-BUILD", Products: []cve.Affected{{Vendor: "microsoft", Product: "sharepoint_server", RangeEndExcl: "16.0.17328.20246"}}}

	if got := m.Match("p", sp("16.0.10337.12109"), []cve.Record{cal2019}); len(got) != 1 {
		t.Fatalf("2019 build (16.0.10337) must map to a 2019 calendar CVE, got %d", len(got))
	}
	if got := m.Match("p", sp("16.0.4306.1001"), []cve.Record{cal2016}); len(got) != 1 {
		t.Fatalf("2016 build (16.0.4306) must map to a 2016 calendar CVE, got %d", len(got))
	}
	if got := m.Match("p", sp("16.0.4306.1001"), []cve.Record{cal2019}); len(got) != 0 {
		t.Fatalf("2016 build must not match a 2019-only CVE, got %d", len(got))
	}
	if got := m.Match("p", sp("15.0.4571"), []cve.Record{cal2013}); len(got) != 1 {
		t.Fatalf("15.0 build must map to 2013, got %d", len(got))
	}
	if got := m.Match("p", sp("16.0.10337.12109"), []cve.Record{buildRange}); len(got) != 1 {
		t.Fatalf("the raw build must still match a build-number range CVE (union), got %d", len(got))
	}
	notSP := cve.Record{CVE: "CVE-Y", Products: []cve.Affected{{Product: "http_server", ExactVersion: "2019"}}}
	if got := m.Match("p", technology.Technology{Product: "http_server", Version: "16.0.10337"}, []cve.Record{notSP}); len(got) != 0 {
		t.Fatalf("normalization must not apply to non-sharepoint products, got %d", len(got))
	}
}
