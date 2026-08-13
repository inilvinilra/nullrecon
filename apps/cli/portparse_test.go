package main

import "testing"

func TestParsePortsRanges(t *testing.T) {
	got := parsePorts("80,443,8000-8002,443")
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("port %d mismatch: got %d", i, got[i])
		}
	}
}

func TestParsePortsIgnoresInvalid(t *testing.T) {
	got := parsePorts("0,70000,-5,abc,22")
	if len(got) != 1 || got[0] != 22 {
		t.Fatalf("invalid ports must be dropped, got %v", got)
	}
}

func TestAllPortsFull(t *testing.T) {
	all := allPorts()
	if len(all) != 65535 || all[0] != 1 || all[65534] != 65535 {
		t.Fatalf("allPorts must cover 1..65535, got len %d", len(all))
	}
}
