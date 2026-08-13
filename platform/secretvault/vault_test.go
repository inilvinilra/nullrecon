package secretvault

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func openTempVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealOpenRoundtrip(t *testing.T) {
	v := openTempVault(t)
	secret := []byte("s3cr3t-value-for-test")
	ref, err := v.Seal("prj-1", secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.OpenSecret(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("s3cr3t-value-for-test")
	if _, err := v.Seal("prj-1", secret); err != nil {
		t.Fatal(err)
	}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return nil
		}
		if bytes.Contains(data, secret) {
			t.Errorf("plaintext secret found in %s", path)
		}
		return nil
	})
}

func TestWrongProjectKeyFails(t *testing.T) {
	v := openTempVault(t)
	ref, err := v.Seal("prj-1", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	other, err := Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	blobPath := filepath.Join(v.dir, "blobs", ref+".json")
	data, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other.dir, "blobs", ref+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenSecret(ref); err == nil {
		t.Fatal("opening with a different keyring must fail")
	}
}

func TestDelete(t *testing.T) {
	v := openTempVault(t)
	ref, err := v.Seal("prj-1", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := v.OpenSecret(ref); err != ErrNotFound {
		t.Fatalf("deleted secret must be gone, got %v", err)
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix permission model")
	}
	v := openTempVault(t)
	if _, err := v.FingerprintKey("prj-1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(v.dir, "keys", "fingerprint-prj-1.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600, got %o", info.Mode().Perm())
	}
}

func TestFingerprintDeterministicAndKeyed(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	f1 := Fingerprint(k1, []byte("secret"))
	if f1 != Fingerprint(k1, []byte("secret")) {
		t.Fatal("fingerprint must be deterministic")
	}
	if f1 == Fingerprint(k2, []byte("secret")) {
		t.Fatal("fingerprint must depend on the key")
	}
	if f1 == Fingerprint(k1, []byte("secret2")) {
		t.Fatal("fingerprint must depend on the value")
	}
}
