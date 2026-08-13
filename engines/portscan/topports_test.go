package portscan

import "testing"

func TestTopPortsBounded(t *testing.T) {
	if got := TopPorts(10); len(got) != 10 || got[0] != 7 {
		t.Fatalf("TopPorts(10) must return first 10 ports, got %v", got)
	}
	all := TopPorts(0)
	if len(all) < 100 {
		t.Fatalf("TopPorts(0) must return the full list, got %d", len(all))
	}
	if got := TopPorts(99999); len(got) != len(all) {
		t.Fatal("oversized n must clamp to full list")
	}
	seen := map[int]bool{}
	for _, p := range all {
		if seen[p] {
			t.Fatalf("duplicate port %d in top list", p)
		}
		if p < 1 || p > 65535 {
			t.Fatalf("invalid port %d", p)
		}
		seen[p] = true
	}
}
