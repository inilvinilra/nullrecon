package fingerprint

import "testing"

func TestHeaderRulesExtractVersion(t *testing.T) {
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
			name:    "varnish via header",
			product: "varnish_cache",
			version: "6.6.1",
			f:       Features{Headers: map[string]string{"via": "1.1 varnish (Varnish/6.6.1)"}},
		},
		{
			name:    "jboss x-powered-by",
			product: "jboss_enterprise_application_platform",
			version: "6.1.0",
			f:       Features{Headers: map[string]string{"x-powered-by": "Servlet/3.0; JBoss-6.1.0"}},
		},
		{
			name:    "directadmin server daemon",
			product: "directadmin",
			version: "1.641",
			f:       Features{Headers: map[string]string{"server": "DirectAdmin Daemon v1.641 Registered"}},
		},
	}
	for _, tc := range cases {
		var got string
		found := false
		for _, tech := range e.Apply(tc.f) {
			if tech.Product == tc.product {
				found = true
				got = tech.Version
			}
		}
		if !found {
			t.Fatalf("%s: product %q was not detected", tc.name, tc.product)
		}
		if got != tc.version {
			t.Fatalf("%s: expected version %q, got %q", tc.name, tc.version, got)
		}
	}
}

func TestNoSpuriousVersionFromNonCaptureRules(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		product string
		f       Features
	}{
		{
			name:    "varnish via without version marker",
			product: "varnish_cache",
			f:       Features{Headers: map[string]string{"via": "1.1 varnish"}},
		},
		{
			name:    "haproxy server name only",
			product: "haproxy",
			f:       Features{Headers: map[string]string{"server": "haproxy"}},
		},
	}
	for _, tc := range cases {
		for _, tech := range e.Apply(tc.f) {
			if tech.Product == tc.product && tech.Version != "" {
				t.Fatalf("%s: a name-only match must not yield a version, got %q", tc.name, tech.Version)
			}
		}
	}
}
