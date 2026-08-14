package tlsscan

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func testSnapshot(t *testing.T) scopeguard.Snapshot {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.CIDRs = []string{"127.0.0.0/8"}
	scope.Protocols = []string{"tcp"}
	scope.PortRanges = []scopeguard.PortRange{{Start: 1, End: 65535}}
	scope.ScanClasses = []string{"tlsscan"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func findingIDs(res Result) map[string]bool {
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.ID] = true
	}
	return ids
}

func TestScanSelfSignedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	e := New(testSnapshot(t), nil)
	res, err := e.Scan(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if res.Cert == nil {
		t.Fatal("certificate must be captured")
	}
	if !res.Protocols["tls1.2"] && !res.Protocols["tls1.3"] {
		t.Fatalf("modern TLS must be detected: %v", res.Protocols)
	}
	if !findingIDs(res)["self-signed-certificate"] {
		t.Fatalf("httptest self-signed cert must be flagged, findings: %+v", res.Findings)
	}
}

func TestEvaluateExpiredWeakSmallKey(t *testing.T) {
	e := New(testSnapshot(t), nil)
	e.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	leaf := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "old.example.com"},
		Issuer:             pkix.Name{CommonName: "old.example.com"},
		NotBefore:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	res := Result{Protocols: map[string]bool{"tls1.0": true, "tls1.2": true}, Cert: &CertInfo{KeyBits: 1024}}
	ids := map[string]bool{}
	for _, f := range e.evaluate(res, leaf, "old.example.com") {
		ids[f.ID] = true
	}
	for _, want := range []string{"certificate-expired", "weak-signature-algorithm", "self-signed-certificate", "weak-rsa-key", "tls-version-1.0"} {
		if !ids[want] {
			t.Fatalf("expected finding %q, got %v", want, ids)
		}
	}
}
