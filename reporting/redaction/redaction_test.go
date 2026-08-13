package redaction

import (
	"strings"
	"testing"
)

func newRedactor(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSecretsRedacted(t *testing.T) {
	r := newRedactor(t)
	cases := []struct {
		name  string
		input string
		raw   string
	}{
		{"bearer", "Authorization: Bearer abcdef123456.token", "abcdef123456.token"},
		{"aws", "key = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"password", `password=hunter2secret`, "hunter2secret"},
		{"cookie", "Cookie: session=xyzprivatevalue", "xyzprivatevalue"},
		{"privatekey", "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----", "MIIEvQ"},
		{"querytoken", "https://a.example/x?token=deadbeefcafe1234&ok=1", "deadbeefcafe1234"},
		{"email", "contact admin@target-internal.example for info", "admin@target-internal.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := r.Redact(tc.input)
			if strings.Contains(res.Text, tc.raw) {
				t.Fatalf("raw value survived redaction: %s", res.Text)
			}
			if len(res.Matched) == 0 {
				t.Fatal("redaction must report matched rules")
			}
		})
	}
}

func TestBenignTextUnchanged(t *testing.T) {
	r := newRedactor(t)
	input := "GET /index.html HTTP/1.1 status 200 length 512"
	res := r.Redact(input)
	if res.Text != input {
		t.Fatalf("benign text must pass through unchanged: %s", res.Text)
	}
}

func TestExtraRule(t *testing.T) {
	r, err := New([]Rule{{Name: "custom", Pattern: `internal-[0-9]+`, Replace: "[REDACTED-ID]"}})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Redact("ref internal-4481 here")
	if strings.Contains(res.Text, "internal-4481") {
		t.Fatal("extra rule must redact")
	}
}

func TestInvalidRuleFailsClosed(t *testing.T) {
	if _, err := New([]Rule{{Name: "broken", Pattern: `([`, Replace: "x"}}); err == nil {
		t.Fatal("invalid rule must fail construction")
	}
}
