package contracts

import "testing"

func TestNewIDFormat(t *testing.T) {
	id := NewID("prj")
	if !ValidID(id) {
		t.Fatalf("id %q does not match expected format", id)
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		id := NewID("ast")
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestValidIDRejects(t *testing.T) {
	for _, bad := range []string{"", "prj", "prj-", "prj-ZZZZZZZZZZZZZZZZZZZZZZZZZZ", "PRJ-00000000000000000000000000", "prj-00000000000000000000000000extra"} {
		if ValidID(bad) {
			t.Fatalf("id %q must be rejected", bad)
		}
	}
}

func TestHashDeterministic(t *testing.T) {
	v := struct {
		A string `json:"a"`
		B int    `json:"b"`
	}{"x", 1}
	h1, err := HashHex(v)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashHex(v)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
}
