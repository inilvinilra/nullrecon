package exposure

import "testing"

func TestNoSignatureMatchesDecoyBodies(t *testing.T) {
	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	decoys := [][]byte{
		[]byte(`<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1><p>Default page.</p></body></html>`),
		[]byte(`<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`),
		[]byte(`<html><head><title>Login</title></head><body><form><input name="user"><input name="pass" type="password"></form></body></html>`),
		[]byte(`<html><body>random marketing content about products and services, contact us at info@example.com</body></html>`),
		[]byte(`{"status":"ok","message":"healthy"}`),
		[]byte(`<html><head><title>500 Internal Server Error</title></head><body>Internal Server Error</body></html>`),
		[]byte(``),
	}
	for _, sig := range set.signatures {
		for _, body := range decoys {
			if _, ok := sig.matches(body); ok {
				t.Fatalf("signature %q falsely matched a decoy body (false positive risk): %q", sig.ID, string(body[:min(60, len(body))]))
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
