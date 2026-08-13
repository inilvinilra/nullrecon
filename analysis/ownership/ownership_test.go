package ownership

import (
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func resolverFixture(t *testing.T) *Resolver {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"safeactive"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.ExactDomains = []string{"exact.net"}
	scope.CIDRs = []string{"203.0.113.0/28"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeSafeActive, now)
	if err != nil {
		t.Fatal(err)
	}
	return NewResolver(snap)
}

func TestResolveHost(t *testing.T) {
	r := resolverFixture(t)
	cases := map[string]asset.OwnershipState{
		"example.com":          asset.OwnExact,
		"exact.net":            asset.OwnExact,
		"deep.sub.example.com": asset.OwnInherited,
		"other.com":            asset.OwnUnknown,
		"example.com.evil.io":  asset.OwnUnknown,
	}
	for host, want := range cases {
		if got := r.ResolveHost(host); got != want {
			t.Fatalf("ResolveHost(%q) = %s, want %s", host, got, want)
		}
	}
}

func TestResolveIP(t *testing.T) {
	r := resolverFixture(t)
	if got := r.ResolveIP("203.0.113.9"); got != asset.OwnExact {
		t.Fatalf("in-cidr ip must be exact, got %s", got)
	}
	if got := r.ResolveIP("192.0.2.44"); got != asset.OwnUnknown {
		t.Fatalf("unknown ip must be unknown, got %s", got)
	}
}

func TestSharedInfra(t *testing.T) {
	if got := SharedInfraState(500, 2); got != asset.OwnSharedInfra {
		t.Fatalf("dense unrelated cohosting must be sharedinfra, got %s", got)
	}
	if got := SharedInfraState(30, 30); got == asset.OwnSharedInfra {
		t.Fatal("mostly in-scope cohosting must not be sharedinfra")
	}
}

func TestCDNEdge(t *testing.T) {
	if !IsCDNEdge("abc.cloudfront.net") {
		t.Fatal("cloudfront host must be cdn edge")
	}
	if IsCDNEdge("example.com") {
		t.Fatal("normal host must not be cdn edge")
	}
}

func TestCombinePrecedence(t *testing.T) {
	if got := Combine([]asset.OwnershipState{asset.OwnUnknown, asset.OwnInherited, asset.OwnExact}); got != asset.OwnExact {
		t.Fatalf("exact must win, got %s", got)
	}
	if got := Combine([]asset.OwnershipState{asset.OwnUnknown}); got != asset.OwnUnknown {
		t.Fatal("unknown alone stays unknown")
	}
	if got := Combine(nil); got != asset.OwnUnknown {
		t.Fatal("empty input fails closed to unknown")
	}
}
