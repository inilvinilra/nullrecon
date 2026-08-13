package scopeguard

import "testing"

func TestPortRangeAuthorization(t *testing.T) {
	snap := Snapshot{Scope: Scope{Ports: []int{22}, PortRanges: []PortRange{{Start: 8000, End: 9000}}}}
	if r, ok := snap.portAllowed(8080, "tcp"); !ok {
		t.Fatalf("port in range must be allowed: %s", r)
	}
	if r, ok := snap.portAllowed(22, "tcp"); !ok {
		t.Fatalf("explicit port must be allowed: %s", r)
	}
	if _, ok := snap.portAllowed(9500, "tcp"); ok {
		t.Fatal("port outside range and list must be blocked")
	}
	empty := Snapshot{Scope: Scope{}}
	if _, ok := empty.portAllowed(80, "tcp"); ok {
		t.Fatal("empty scope must fail closed on ports")
	}
}
