package dnsbrute

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

type fakeResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if ips, ok := f.hosts[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return host, nil
}

func snapshot(t *testing.T, mode policy.Mode) scopeguard.Snapshot {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{string(mode)}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	snap, err := scopeguard.Compile(project, authz, scope, mode, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestDiscoverResolvesOnlyLiveNames(t *testing.T) {
	fake := fakeResolver{hosts: map[string][]string{
		"www.example.com": {"93.184.216.34"},
		"api.example.com": {"93.184.216.35", "93.184.216.35"},
	}}
	e := New(snapshot(t, policy.ModeSafeActive), nil).WithResolver(fake)
	summary, err := e.Discover(context.Background(), "example.com", Options{Words: []string{"www", "api", "ghost", "nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tested != 4 {
		t.Fatalf("expected 4 candidates tested, got %d", summary.Tested)
	}
	if summary.Resolved != 2 {
		t.Fatalf("only live names must resolve (zero false positives), got %d: %+v", summary.Resolved, summary.Results)
	}
	got := map[string]bool{}
	for _, r := range summary.Results {
		got[r.Host] = true
		if len(r.IPs) == 0 {
			t.Fatalf("resolved result must carry IPs: %+v", r)
		}
	}
	if !got["www.example.com"] || !got["api.example.com"] {
		t.Fatalf("expected www and api resolved, got %v", got)
	}
}

func TestDiscoverDedupesIPs(t *testing.T) {
	fake := fakeResolver{hosts: map[string][]string{"www.example.com": {"1.1.1.1", "1.1.1.1", "2.2.2.2"}}}
	e := New(snapshot(t, policy.ModeSafeActive), nil).WithResolver(fake)
	summary, _ := e.Discover(context.Background(), "example.com", Options{Words: []string{"www"}})
	if len(summary.Results) != 1 || len(summary.Results[0].IPs) != 2 {
		t.Fatalf("duplicate IPs must be collapsed: %+v", summary.Results)
	}
}

func TestDiscoverScopeGatesOutOfScopeDomain(t *testing.T) {
	fake := fakeResolver{hosts: map[string][]string{"www.evil.com": {"6.6.6.6"}}}
	e := New(snapshot(t, policy.ModeSafeActive), nil).WithResolver(fake)
	summary, _ := e.Discover(context.Background(), "evil.com", Options{Words: []string{"www"}})
	if summary.Resolved != 0 || summary.Blocked == 0 {
		t.Fatalf("out-of-scope domain must be blocked before resolution: %+v", summary)
	}
}

func TestDefaultWordsLoaded(t *testing.T) {
	words := DefaultWords()
	if len(words) < 100 {
		t.Fatalf("embedded wordlist should be substantial, got %d", len(words))
	}
	for _, w := range words {
		if w == "" {
			t.Fatal("wordlist must not contain empty entries")
		}
	}
}
