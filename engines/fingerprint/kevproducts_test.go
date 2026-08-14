package fingerprint

import "testing"

func TestKEVProductFingerprints(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	detect := map[string]Features{
		"connect_secure":          {Cookies: []string{"DSID=abcdef0123456789; secure"}},
		"metabase":                {BodySnippet: `<div id="root"></div><script>var __MB_ = {}; metabase-bootstrap</script>`},
		"screenconnect":           {BodySnippet: `<html><body>ScreenConnect by Elsinore Technologies scScriptData</body></html>`},
		"ofbiz":                   {Cookies: []string{"OFBiz.Visitor=10000; path=/"}},
		"teamcity":                {BodySnippet: `<html><body>JetBrains TeamCity tc-header</body></html>`},
		"papercut_mf":             {BodySnippet: `<html><body>PaperCut MF login com.papercut</body></html>`},
		"endpoint_manager_mobile": {BodySnippet: `<html><body>MobileIron corePropertyBundle</body></html>`},
	}
	for product, f := range detect {
		found := false
		for _, tech := range e.Apply(f) {
			if tech.Product == product {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s must be detected: %+v", product, e.Apply(f))
		}
	}

	versioned := []struct {
		product, version string
		f                Features
	}{
		{"cacti", "1.2.22", Features{BodySnippet: `<html><body>The Cacti Group - cacti_version='1.2.22'</body></html>`}},
		{"geoserver", "2.23.0", Features{BodySnippet: `<html><body>org.geoserver powered GeoServer 2.23.0 configuration</body></html>`}},
	}
	for _, tc := range versioned {
		var got string
		found := false
		for _, tech := range e.Apply(tc.f) {
			if tech.Product == tc.product {
				found = true
				got = tech.Version
			}
		}
		if !found {
			t.Fatalf("%s must be detected", tc.product)
		}
		if got != tc.version {
			t.Fatalf("%s: expected version %q, got %q", tc.product, tc.version, got)
		}
	}
}
