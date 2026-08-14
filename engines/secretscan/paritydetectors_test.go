package secretscan

import (
	"strings"
	"testing"
)

func TestParityDetectorsRecall(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	hex := strings.Repeat("9f2c7b4e8a1d6035af92e7c4b0d8f135", 6) // 192 hex chars, no placeholder runs
	alnum := "9f2c7b4e8a1d6035af92e7c4b0d8f1359f2c7b4e8a1d6035af92e7c4b0d8"
	real := map[string]string{
		"cloudflare-origin-ca-key": "v1.0-" + hex[:171],
		"alibaba-access-key":       "LTAI" + "5tGkR7mNqPwXzYbVcE9d",
		"flutterwave-secret-key":   "FLWSECK-" + hex[:32] + "-X",
		"clojars-token":            "CLOJARS_" + alnum[:60],
		"grafana-cloud-token":      "glc_" + "9f2c7b4e8a1d6035af92e7c4b0d8f135QwRt",
		"frameio-token":            "fio-u-" + alnum[:58] + "9fXk7Q",
	}
	for id, secret := range real {
		res := Scan(set, []byte("token = \""+secret+"\""), "config")
		hit := false
		for _, c := range res.Candidates {
			if c.DetectorID == id {
				hit = true
			}
		}
		if !hit {
			t.Errorf("RECALL FAIL: detector %q did not fire on a real-format token", id)
		}
	}

	placeholders := []string{
		"LTAI" + "xxxxxxxxxxxxxxxxxxxx",
		"CLOJARS_" + "your_token_here_placeholder_changeme_example_value_goes_here0",
		"glc_" + "example_changeme_placeholder_token_value_here",
	}
	for _, p := range placeholders {
		res := Scan(set, []byte("token = \""+p+"\""), "config")
		if len(res.Candidates) != 0 {
			t.Errorf("placeholder %q must be suppressed, got %d hits", p, len(res.Candidates))
		}
	}
}
