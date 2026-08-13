package secretscan

import "testing"

func TestComprehensiveRecall(t *testing.T) {
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
	realSecrets := map[string]string{
		"aws-access-key":     "AKIA" + "QYLPZ7K3JX2N4M8R",
		"github-token":       "ghp_" + fill(36),
		"github-pat-fine":    "github_pat_" + fill(30),
		"gitlab-pat":         "glpat-" + fill(20),
		"slack-token":        "xoxb-" + "2854392844-8f3kD9mZ2pQ7rT4xY1cV",
		"slack-webhook":      "https://hooks.slack.com/services/T024BE7L9/B0G7Q3ZK5/" + fill(24),
		"stripe-secret":      "sk_live_" + fill(24),
		"google-api-key":     "AIza" + fill(35),
		"sendgrid-api-key":   "SG." + fill(22) + "." + fill(43),
		"npm-token":          "npm_" + fill(36),
		"openai-api-key":     "sk-" + fill(20) + "T3BlbkFJ" + fill(20),
		"anthropic-api-key":  "sk-ant-" + fill(30),
		"huggingface-token":  "hf_" + fill(34),
		"digitalocean-token": "dop_v1_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		"private-key":        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
		"jwt":                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + fill(20),
		"twilio-api-key":     "SK" + "3f8a1c9e2b7d4056af13e89c02d6b7f4",
		"aws-mws-token":      "amzn.mws.4ea38b7b-f563-7709-4bae-87aeae1234b8",
	}
	detected := map[string]bool{}
	for _, secret := range realSecrets {
		res := Scan(set, []byte("key = "+secret), "config")
		for _, c := range res.Candidates {
			detected[c.DetectorID] = true
		}
	}
	missed := []string{}
	for id := range realSecrets {
		if !detected[id] {
			missed = append(missed, id)
		}
	}
	if len(missed) > 2 {
		t.Fatalf("recall too low: %d/%d detected, missed %v", len(realSecrets)-len(missed), len(realSecrets), missed)
	}
	t.Logf("recall: %d/%d real-format secrets detected", len(realSecrets)-len(missed), len(realSecrets))
}
