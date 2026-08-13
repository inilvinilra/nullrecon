package fingerprint

import "testing"

func TestDefaultEngineLoads(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatalf("DefaultEngine must load embedded ruleset: %v", err)
	}
	if e == nil {
		t.Fatal("engine is nil")
	}
	got := e.Apply(Features{Headers: map[string]string{"server": "Apache/2.4.62 (Unix) OpenSSL/1.0.2k-fips"}})
	if len(got) == 0 {
		t.Fatalf("embedded ruleset must detect apache+openssl: %+v", got)
	}
}
