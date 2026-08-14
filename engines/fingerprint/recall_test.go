package fingerprint

import "testing"

func TestHardenedCMSRulesStillDetect(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Features{
		"wordpress": {BodySnippet: `<link rel="stylesheet" href="https://x/wp-content/themes/twentytwenty/style.css">`},
		"joomla":    {BodySnippet: `<script src="/media/jui/js/jquery.min.js"></script>`},
		"drupal":    {BodySnippet: `<script src="/sites/all/modules/x/y.js"></script>`},
		"magento":   {BodySnippet: `<link href="/skin/frontend/default/theme/css/styles.css">`},
	}
	for product, f := range cases {
		got := e.Apply(f)
		found := false
		for _, tech := range got {
			if tech.Product == product {
				found = true
			}
		}
		if !found {
			t.Fatalf("RECALL FAIL: hardened %s rule no longer detects a real asset-linked page: %+v", product, got)
		}
	}
}
