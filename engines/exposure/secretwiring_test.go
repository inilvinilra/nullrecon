package exposure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nullrecon/nullrecon/engines/secretscan"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

// When secret detectors are wired, an exposed .env must not only be flagged
// as a leak but have its embedded credentials extracted, classified, and
// escalated - with redacted previews so the raw secret never leaves the engine.
func TestScanExtractsSecretsWhenDetectorsWired(t *testing.T) {
	// Assembled at runtime so the literal tokens never appear in source
	// (avoids tripping upstream secret-scanning push protection); each half
	// is inert on its own but reconstructs a real-format token for the engine.
	awsKey := "AKIA" + "Z3QYLPK7X2N4M8RD"
	stripeKey := "sk_live_" + "9zK4mN2pQ7rT4xY1cV5bN0mL"
	dbPass := "Super" + "SecretDbPass123"
	envBody := "APP_ENV=production\nDB_PASSWORD=" + dbPass + "\n" +
		"AWS_ACCESS_KEY_ID=" + awsKey + "\nSTRIPE_SECRET=" + stripeKey + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte(envBody))
			return
		}
		w.Write([]byte("<html><body>not found</body></html>"))
	}))
	defer srv.Close()

	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	detectors, err := secretscan.DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	red, _ := redaction.New(nil)
	snap := snapshotForHost(t, hostOf(t, srv.URL))
	e := New(snap, nil, red, set).WithSecretDetectors(detectors)

	res, err := e.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var env *Finding
	for i := range res.Findings {
		if res.Findings[i].SignatureID == "env-file" {
			env = &res.Findings[i]
		}
	}
	if env == nil {
		t.Fatalf("exposed .env must be confirmed: %+v", res.Findings)
	}
	if len(env.Secrets) < 2 {
		t.Fatalf("wired detectors must extract embedded secrets, got %d: %+v", len(env.Secrets), env.Secrets)
	}
	got := map[string]bool{}
	for _, s := range env.Secrets {
		got[s.DetectorID] = true
		if s.Preview == "" {
			t.Fatalf("secret %q must carry a redacted preview", s.DetectorID)
		}
		if strings.Contains(s.Preview, awsKey) || strings.Contains(s.Preview, dbPass) {
			t.Fatalf("preview must never contain the raw secret: %q", s.Preview)
		}
	}
	if !got["aws-access-key"] || !got["stripe-secret"] {
		t.Fatalf("expected aws-access-key and stripe-secret to be detected, got %v", got)
	}
	if env.Severity != "critical" {
		t.Fatalf("an exposed file carrying live secrets must escalate to critical, got %q", env.Severity)
	}
}
