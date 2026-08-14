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
