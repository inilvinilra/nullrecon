package dnscan

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

type mockResolver struct {
	hosts  map[string][]string
	cnames map[string]string
}

func (m mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if v, ok := m.hosts[host]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func (m mockResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if v, ok := m.cnames[host]; ok {
		return v, nil
	}
	return host + ".", nil
}

func (m mockResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return nil, errors.New("no mx")
}

func (m mockResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return nil, errors.New("no ns")
}

func (m mockResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return nil, errors.New("no txt")
}

func (m mockResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, errors.New("no ptr")
}

func snapshotFor(t *testing.T, scope scopeguard.Scope, mode policy.Mode) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"passive", "safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	snap, err := scopeguard.Compile(project, authz, scope, mode, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestResolveInScope(t *testing.T) {
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.CIDRs = []string{"192.0.2.0/24"}
	snap := snapshotFor(t, scope, policy.ModeSafeActive)
	resolver := mockResolver{
		hosts:  map[string][]string{"www.example.com": {"192.0.2.10"}},
		cnames: map[string]string{"www.example.com": "cdn.example.com."},
	}
	e := New(snap, nil, resolver)
	res, err := e.Resolve(context.Background(), "www.example.com", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.A) != 1 || res.A[0] != "192.0.2.10" {
		t.Fatalf("bad A records: %+v", res)
	}
	if res.CNAME != "cdn.example.com" {
		t.Fatalf("bad cname: %+v", res)
	}
	if len(res.Blocked) != 0 {
		t.Fatalf("no pivot should be blocked: %+v", res.Blocked)
	}
}

func TestOutOfScopePivotBlocked(t *testing.T) {
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.CIDRs = []string{"192.0.2.0/24"}
	snap := snapshotFor(t, scope, policy.ModeSafeActive)
	resolver := mockResolver{
		hosts:  map[string][]string{"www.example.com": {"198.51.100.7"}},
		cnames: map[string]string{"www.example.com": "attacker.other.net."},
	}
	e := New(snap, nil, resolver)
	res, err := e.Resolve(context.Background(), "www.example.com", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.A) != 0 {
		t.Fatalf("out-of-scope resolved ip must be dropped: %+v", res.A)
	}
	if res.CNAME != "" {
		t.Fatalf("out-of-scope cname must be dropped: %s", res.CNAME)
	}
	if len(res.Blocked) != 2 {
		t.Fatalf("both pivots must be reported blocked: %+v", res.Blocked)
	}
}

func TestQueryBudgetEnforced(t *testing.T) {
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.CIDRs = []string{"192.0.2.0/24"}
	snap := snapshotFor(t, scope, policy.ModeSafeActive)
	resolver := mockResolver{hosts: map[string][]string{"www.example.com": {"192.0.2.10"}}}
	budget := budgetguard.New("test", budgetguard.Budget{budgetguard.DimRequests: 1}, nil)
	e := New(snap, budget, resolver)
	res, err := e.Resolve(context.Background(), "www.example.com", 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, msg := range res.Errors {
		if strings.Contains(msg, "budget") {
			found = true
		}
	}
	if !found {
		t.Fatalf("budget exhaustion must be reported, errors: %+v", res.Errors)
	}
}

func TestMaxQueriesRespected(t *testing.T) {
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	scope.CIDRs = []string{"192.0.2.0/24"}
	snap := snapshotFor(t, scope, policy.ModeSafeActive)
	resolver := mockResolver{hosts: map[string][]string{"www.example.com": {"192.0.2.10"}}}
	e := New(snap, nil, resolver)
	res, _ := e.Resolve(context.Background(), "www.example.com", 2)
	if len(res.MX) != 0 || len(res.NS) != 0 || len(res.TXT) != 0 {
		t.Fatalf("query budget of 2 must stop later lookups: %+v", res)
	}
	if len(res.A) != 1 {
		t.Fatalf("first lookup must succeed: %+v", res)
	}
}
