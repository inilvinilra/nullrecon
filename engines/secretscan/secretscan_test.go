package secretscan

import (
	"fmt"
	"strings"
	"testing"
)

func TestScanConfirmsRealSecretsAndSuppressesNoise(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	awsKey := "AKIA" + strings.Repeat("Z3", 8)
	ghToken := "ghp_" + strings.Repeat("Ab3Kp9", 6)
	content := fmt.Sprintf(`
service config
  aws_key = %s
  github_token = %s
  example_key = AKIAIOSFODNN7EXAMPLE
  api_key = "your_api_key_value"
-----BEGIN RSA PRIVATE KEY-----
MIIabcNotARealKeyBodyHere
-----END RSA PRIVATE KEY-----
`, awsKey, ghToken)

	res := Scan(set, []byte(content), "config.yaml")

	confirmed := map[string]Candidate{}
	for _, c := range res.Candidates {
		confirmed[c.DetectorID] = c
	}
	for _, id := range []string{"aws-access-key", "github-token", "private-key"} {
		if _, ok := confirmed[id]; !ok {
			t.Fatalf("detector %q must confirm a real secret: %+v", id, res.Candidates)
		}
	}
	if res.Suppressed < 2 {
		t.Fatalf("the AWS example key and the placeholder must be suppressed, suppressed=%d", res.Suppressed)
	}
	for _, c := range res.Candidates {
		if strings.Contains(c.Preview, awsKey) || strings.Contains(c.Preview, ghToken) {
			t.Fatalf("preview must never contain the raw secret: %q", c.Preview)
		}
		if len(c.Fingerprint) != 64 {
			t.Fatalf("fingerprint must be a sha256 hex digest, got %q", c.Fingerprint)
		}
		if c.State != "confirmed" {
			t.Fatalf("only confirmed candidates should be returned, got %q", c.State)
		}
	}
}

func TestExampleKeyIsPlaceholder(t *testing.T) {
	if !isPlaceholder("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("the documented AWS example key must be treated as a placeholder")
	}
	if !isPlaceholder("your_api_key_here") {
		t.Fatal("your_* placeholders must be detected")
	}
	if !isPlaceholder("aaaaaaaaaaaa") {
		t.Fatal("repeated runs must be treated as placeholders")
	}
	if isPlaceholder("R8xKp2Lq7Wm4Nb8Rt5Vy") {
		t.Fatal("a high-entropy value must not be flagged as a placeholder")
	}
}

func TestEntropyGate(t *testing.T) {
	high := shannonEntropy("R8xKp2Lq7Wm4Nb8Rt5Vy3Hc6Jf1Dg0St")
	low := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")
	if high <= low {
		t.Fatalf("high-entropy string must score above a repeated one: %f vs %f", high, low)
	}
	if low > 1.0 {
		t.Fatalf("a single-character run must have near-zero entropy, got %f", low)
	}
}

func TestExpandedDetectorsMatchRealTokens(t *testing.T) {
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
	cases := map[string]string{
		"gitlab-pat":         "glpat-" + fill(20),
		"stripe-secret":      "sk_live_" + fill(24),
		"slack-webhook":      "https://hooks.slack.com/services/T024BE7L9/B0G7Q3ZK5/" + fill(24),
		"sendgrid-api-key":   "SG." + fill(22) + "." + fill(43),
		"huggingface-token":  "hf_" + fill(34),
		"telegram-bot-token": "847362910:" + fill(35),
		"basic-auth-url":     "postgres://admin:S3cretP4ssw0rd@db.internal:5432/app",
	}
	for id, secret := range cases {
		content := "value = " + secret + "\n"
		res := Scan(set, []byte(content), "test")
		found := false
		for _, c := range res.Candidates {
			if c.DetectorID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("detector %q must match a real token; candidates=%+v suppressed=%d", id, res.Candidates, res.Suppressed)
		}
	}
}

func TestDetectorCountGrew(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() < 40 {
		t.Fatalf("expected a comprehensive detector set, got %d", set.Len())
	}
}
