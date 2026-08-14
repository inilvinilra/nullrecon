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
		{
			name:    "phpmyadmin version in title",
			product: "phpmyadmin",
			version: "5.2.1",
			f:       Features{BodySnippet: `<title>phpMyAdmin 5.2.1</title><input name="pma_username">`},
		},
		{
			name:    "adminer version in title",
			product: "adminer",
			version: "4.8.1",
			f:       Features{BodySnippet: `<title>Login - Adminer 4.8.1</title><form name="auth[server]">`},
		},
		{
			name:    "typo3 generator version",
			product: "typo3",
			version: "11.5.0",
			f:       Features{BodySnippet: `<meta name="generator" content="TYPO3 CMS 11.5.0">`},
		},
		{
			name:    "font awesome cdn path version",
			product: "font_awesome",
			version: "6.4.0",
			f:       Features{BodySnippet: `<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">`},
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
