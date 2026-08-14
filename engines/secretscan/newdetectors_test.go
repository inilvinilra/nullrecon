package secretscan

import "testing"

func TestNewDetectorsRecallAndPlaceholderSuppression(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	fill := func(n int) string {
		base := "aB3xY7zK9mN2pQ4rS6tU8vW1cV5bN0mL3kJ6hG9fD2sA4tE6uH8iL1oP7wQjR"
		out := ""
		for len(out) < n {
			out += base
		}
		return out[:n]
	}
	real := map[string]string{
		"linear-api-key":          "lin_api_" + fill(40),
		"planetscale-token":       "pscale_tkn_" + fill(40),
		"planetscale-password":    "pscale_pw_" + fill(40),
		"doppler-token":           "dp.pt." + fill(43),
		"grafana-service-account": "glsa_" + fill(32) + "_a1b2c3d4",
		"dockerhub-pat":           "dckr_pat_" + fill(30),
		"atlassian-api-token":     "ATATT3" + fill(160),
		"dropbox-token":           "sl." + fill(140),
		"figma-token":             "figd_" + fill(44),
		"clickup-token":           "pk_9048213_K7QZ4M2X9BV6NR3TWJ5PLH0DCFGYU8ES",
		"stripe-restricted-key":   "rk_live_" + fill(28),
		"razorpay-key":            "rzp_live_" + fill(14),
		"hashicorp-vault-token":   "hvs." + fill(100),
		"terraform-cloud-token":   fill(14) + ".atlasv1." + fill(65),
		"prefect-api-key":         "pnu_" + fill(36),
		"openai-project-key":      "sk-proj-" + fill(48),
	}
	for id, secret := range real {
		res := Scan(set, []byte("secret = \""+secret+"\""), "config")
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

	// Placeholders and template values must never be reported.
	placeholders := []string{
		"lin_api_your_api_key_placeholder_goes_here_000",
		"dckr_pat_replace_me_with_a_real_token_example",
		"sk-proj-example-value-changeme-changeme-changeme",
		"hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	for _, p := range placeholders {
		res := Scan(set, []byte("token = \""+p+"\""), "config")
		if len(res.Candidates) != 0 {
			t.Errorf("placeholder %q must be suppressed, got %d hits", p, len(res.Candidates))
		}
	}
}
