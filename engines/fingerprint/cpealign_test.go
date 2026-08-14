package fingerprint

import (
	"strings"
	"testing"
)

func TestProductNamesAreCVEStoreAligned(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		product string
		version string
		f       Features
	}{
		{
			name:    "iis aligns to internet_information_services",
			product: "internet_information_services",
			version: "7.5",
			f:       Features{Headers: map[string]string{"server": "Microsoft-IIS/7.5"}},
		},
		{
			name:    "exchange aligns to exchange_server",
			product: "exchange_server",
			f:       Features{Headers: map[string]string{"x-owa-version": "15.1.2507.6"}},
		},
		{
			name:    "gunicorn header variant keeps gunicorn name",
			product: "gunicorn",
			version: "20.1.0",
			f:       Features{Headers: map[string]string{"server": "gunicorn/20.1.0"}},
		},
	}
	for _, tc := range cases {
		var tech *technologyView
		for _, got := range e.Apply(tc.f) {
			if got.Product == tc.product {
				tech = &technologyView{product: got.Product, version: got.Version, cpe: got.CPE}
			}
		}
		if tech == nil {
			t.Fatalf("%s: expected product %q to be detected", tc.name, tc.product)
		}
		if tc.version != "" && tech.version != tc.version {
			t.Fatalf("%s: expected version %q, got %q", tc.name, tc.version, tech.version)
		}
		if len(tech.cpe) == 0 || !strings.Contains(tech.cpe[0], tc.product) {
			t.Fatalf("%s: CPE must reference the aligned product name, got %v", tc.name, tech.cpe)
		}
	}
}

type technologyView struct {
	product string
	version string
	cpe     []string
}
