package orchestrator

import (
	"testing"

	"github.com/nullrecon/nullrecon/core/scopeguard"
)

func TestExpandScopePortsMergesRangesAndDedupes(t *testing.T) {
	got := expandScopePorts(scopeguard.Scope{
		Ports:      []int{80, 443, 8080},
		PortRanges: []scopeguard.PortRange{{Start: 8079, End: 8081}},
	})
	seen := map[int]bool{}
	for _, p := range got {
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
	for _, want := range []int{80, 443, 8079, 8080, 8081} {
		if !seen[want] {
			t.Fatalf("expected port %d in expansion, got %v", want, got)
		}
	}
}

func TestExpandScopePortsFullRange(t *testing.T) {
	got := expandScopePorts(scopeguard.Scope{PortRanges: []scopeguard.PortRange{{Start: 1, End: 65535}}})
	if len(got) != 65535 {
		t.Fatalf("full range must expand to 65535 ports, got %d", len(got))
	}
}
