package fingerprint

import "testing"

// Body-based rules must extract a version from their capture group, just like
// header rules. A regression here (matchRule returning empty text for body
// matches) silently drops CMS/library versions, which breaks downstream CVE
// matching even though the product is still identified.
func TestBodyRulesExtractVersion(t *testing.T) {
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
			name:    "wordpress generator meta",
			product: "wordpress",
			version: "6.4.2",
			f:       Features{BodySnippet: `<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x.css">`},
		},
		{
			name:    "jquery versioned asset query",
			product: "jquery",
			version: "3.7.1",
			f:       Features{BodySnippet: `<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>`},
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
			t.Fatalf("%s: expected version %q from a body rule, got %q", tc.name, tc.version, got)
		}
	}
}
