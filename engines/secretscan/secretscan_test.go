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
