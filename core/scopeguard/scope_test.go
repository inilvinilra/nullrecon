package scopeguard

import (
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func fixture(now time.Time) (identity.Project, identity.Authorization, Scope) {
	project := identity.NewProject("Test", "test")
	authz := identity.NewAuthorization(project.ID, "bug-bounty-program", "https://example.com/scope", []string{"passive", "safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	scope := NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.ExactDomains = []string{"exact-only.net"}
	scope.CIDRs = []string{"203.0.113.0/28"}
	scope.IPs = []string{"192.0.2.10"}
	scope.Ports = []int{80, 443, 8443}
	scope.Protocols = []string{"tcp"}
	scope.DeniedAssets = []string{"donotouch.example.com", "198.51.100.0/24"}
	scope.DeniedPaths = []string{"/admin/purge"}
	scope.DeniedActions = []string{"credentialvalidate"}
	scope.ScanClasses = []string{"contentdiscovery"}
	return project, authz, scope
}

func compile(t *testing.T, now time.Time) Snapshot {
	t.Helper()
	project, authz, scope := fixture(now)
	snap, err := Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return snap
}

func TestCompileRejectsExpiredAuthorization(t *testing.T) {
	now := time.Now().UTC()
	project, _, scope := fixture(now)
	expired := identity.NewAuthorization(project.ID, "old", "", []string{"safeactive"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if _, err := Compile(project, expired, scope, policy.ModeSafeActive, now); err == nil {
		t.Fatal("expired authorization must fail compilation")
	}
}

func TestCompileRejectsModeOutsideAuthorization(t *testing.T) {
	now := time.Now().UTC()
	project, _, scope := fixture(now)
	passiveOnly := identity.NewAuthorization(project.ID, "program", "", []string{"passive"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := Compile(project, passiveOnly, scope, policy.ModeAuthorizedTest, now); err == nil {
		t.Fatal("mode outside authorization must fail compilation")
	}
}

func TestCompileRejectsInvalidScope(t *testing.T) {
	now := time.Now().UTC()
	project, authz, scope := fixture(now)
	scope.CIDRs = []string{"not-a-cidr"}
	if _, err := Compile(project, authz, scope, policy.ModeSafeActive, now); err == nil {
		t.Fatal("invalid cidr must fail compilation")
	}
}

func TestEvaluateAllowsInScopeSubdomain(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	d := snap.Evaluate(Target{Host: "api.example.com", Port: 443, Protocol: "tcp"}, now)
	if !d.Allowed || d.Class != asset.ClassActive {
		t.Fatalf("in-scope subdomain must be active: %+v", d)
	}
}

func TestEvaluateRejectsUnknownHost(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	d := snap.Evaluate(Target{Host: "evil.other.com", Port: 443}, now)
	if d.Allowed || d.Class != asset.ClassUnknown {
		t.Fatalf("unknown host must fail closed: %+v", d)
	}
}

func TestEvaluateDeniedWins(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	d := snap.Evaluate(Target{Host: "donotouch.example.com", Port: 443}, now)
	if d.Allowed || d.Class != asset.ClassDenied {
		t.Fatalf("denied asset must stay denied even inside root domain: %+v", d)
	}
}

func TestEvaluateDeniedPath(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	d := snap.Evaluate(Target{Host: "example.com", Path: "/admin/purge/now", Port: 443}, now)
	if d.Allowed {
		t.Fatalf("denied path must be blocked: %+v", d)
	}
}

func TestEvaluatePortNotListed(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	d := snap.Evaluate(Target{Host: "example.com", Port: 22}, now)
	if d.Allowed {
		t.Fatalf("unlisted port must fail closed: %+v", d)
	}
}

func TestEvaluateCIDRMembership(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	if d := snap.Evaluate(Target{IP: "203.0.113.5"}, now); !d.Allowed {
		t.Fatalf("ip inside allowed cidr must be allowed: %+v", d)
	}
	if d := snap.Evaluate(Target{IP: "203.0.113.200"}, now); d.Allowed {
		t.Fatal("ip outside allowed cidr must be denied")
	}
	if d := snap.Evaluate(Target{IP: "198.51.100.7"}, now); d.Allowed || d.Class != asset.ClassDenied {
		t.Fatalf("ip inside denied range must be denied: %+v", d)
	}
}

func TestPivotReevaluation(t *testing.T) {
	now := time.Now().UTC()
	snap := compile(t, now)
	from := Target{Host: "example.com"}
	d := snap.EvaluatePivot(from, Target{Host: "cdn.other-vendor.net"}, now)
	if d.Allowed {
		t.Fatalf("out-of-scope pivot must fail closed: %+v", d)
	}
	d = snap.EvaluatePivot(from, Target{Host: "static.example.com"}, now)
	if !d.Allowed {
		t.Fatalf("in-scope pivot must be allowed: %+v", d)
	}
}

func TestTimeWindowsFailClosed(t *testing.T) {
	now := time.Now().UTC()
	project, authz, scope := fixture(now)
	scope.TimeWindows = []TimeWindow{{StartUTC: "02:00", EndUTC: "04:00"}}
	snap, err := Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	inside := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, time.UTC)
	outside := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	if d := snap.Evaluate(Target{Host: "example.com"}, inside); !d.Allowed {
		t.Fatalf("inside window must be allowed: %+v", d)
	}
	if d := snap.Evaluate(Target{Host: "example.com"}, outside); d.Allowed {
		t.Fatal("outside window must fail closed")
	}
}

func TestDeniedActionBlocksAuthorizedMode(t *testing.T) {
	now := time.Now().UTC()
	project, authz, scope := fixture(now)
	snap, err := Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	d := snap.EvaluateAction(Target{Host: "example.com", Port: 443}, policy.ActionCredentialValidate, now)
	if d.Allowed {
		t.Fatal("denied action must be blocked even in authorizedtest mode")
	}
}

func TestGrantedScanClassFlowsToPolicy(t *testing.T) {
	now := time.Now().UTC()
	project, authz, scope := fixture(now)
	snap, err := Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := snap.EvaluateAction(Target{Host: "example.com", Port: 443}, policy.ActionContentDiscovery, now); !d.Allowed {
		t.Fatalf("granted contentdiscovery must be allowed: %+v", d)
	}
	if d := snap.EvaluateAction(Target{Host: "example.com", Port: 443}, policy.ActionVulnTemplate, now); d.Allowed {
		t.Fatal("ungranted vulntemplate must be blocked")
	}
}

func TestSnapshotHashDeterministic(t *testing.T) {
	now := time.Now().UTC()
	project, authz, scope := fixture(now)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	authz.ValidFrom = fixed.Add(-time.Hour)
	authz.ValidTo = fixed.Add(24 * time.Hour)
	s1, err := Compile(project, authz, scope, policy.ModeSafeActive, fixed)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Compile(project, authz, scope, policy.ModeSafeActive, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Hash != s2.Hash {
		t.Fatal("snapshot hash must be reproducible for identical inputs")
	}
}
