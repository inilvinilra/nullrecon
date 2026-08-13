package secretvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nullrecon/nullrecon/contracts"
)

var ErrNotFound = errors.New("secretvault: secret not found")

const blobVersion = "nr.vaultblob/v1"

type blob struct {
	Version    string `json:"version"`
	ProjectID  string `json:"projectId"`
	WrappedDEK string `json:"wrappedDek"`
	Nonce      string `json:"nonce"`
	Body       string `json:"body"`
	Hash       string `json:"hash"`
}

type Vault struct {
	dir     string
	keyring *FileKeyring
}

func Open(dir string) (*Vault, error) {
	keyring, err := NewFileKeyring(filepath.Join(dir, "keys"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	return &Vault{dir: dir, keyring: keyring}, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func (v *Vault) Seal(projectID string, plaintext []byte) (string, error) {
	kek, err := v.keyring.GetOrCreate("project-" + projectID)
	if err != nil {
		return "", err
	}
	dek, err := randomKey()
	if err != nil {
		return "", err
	}
	kekGCM, err := gcm(kek)
	if err != nil {
		return "", err
	}
	dekGCM, err := gcm(dek)
	if err != nil {
		return "", err
	}
	wrapNonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	bodyNonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	wrapped := kekGCM.Seal(nil, wrapNonce, dek, []byte(projectID))
	body := dekGCM.Seal(nil, bodyNonce, plaintext, []byte(projectID))
	b := blob{
		Version:    blobVersion,
		ProjectID:  projectID,
		WrappedDEK: hex.EncodeToString(append(wrapNonce, wrapped...)),
		Nonce:      hex.EncodeToString(bodyNonce),
		Body:       hex.EncodeToString(body),
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	b.Hash = contracts.HashBytes(data)
	data, err = json.Marshal(b)
	if err != nil {
		return "", err
	}
	ref := contracts.NewID("blob")
	path := filepath.Join(v.dir, "blobs", ref+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return ref, nil
}

func (v *Vault) OpenSecret(ref string) ([]byte, error) {
	path := filepath.Join(v.dir, "blobs", ref+".json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var b blob
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Version != blobVersion {
		return nil, fmt.Errorf("secretvault: unsupported blob version %q", b.Version)
	}
	check := b
	check.Hash = ""
	checkData, err := json.Marshal(check)
	if err != nil {
		return nil, err
	}
	if contracts.HashBytes(checkData) != b.Hash {
		return nil, fmt.Errorf("secretvault: blob integrity check failed")
	}
	kek, err := v.keyring.Get("project-" + b.ProjectID)
	if err != nil {
		return nil, err
	}
	kekGCM, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	wrappedRaw, err := hex.DecodeString(b.WrappedDEK)
	if err != nil {
		return nil, err
	}
	if len(wrappedRaw) < kekGCM.NonceSize() {
		return nil, fmt.Errorf("secretvault: corrupt wrapped key")
	}
	dek, err := kekGCM.Open(nil, wrappedRaw[:kekGCM.NonceSize()], wrappedRaw[kekGCM.NonceSize():], []byte(b.ProjectID))
	if err != nil {
		return nil, fmt.Errorf("secretvault: unwrap failed: %w", err)
	}
	dekGCM, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	bodyNonce, err := hex.DecodeString(b.Nonce)
	if err != nil {
		return nil, err
	}
	body, err := hex.DecodeString(b.Body)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, bodyNonce, body, []byte(b.ProjectID))
	if err != nil {
		return nil, fmt.Errorf("secretvault: open failed: %w", err)
	}
	return plaintext, nil
}

func (v *Vault) Delete(ref string) error {
	path := filepath.Join(v.dir, "blobs", ref+".json")
	data, err := os.ReadFile(path)
	if err == nil {
		zeroed := make([]byte, len(data))
		if werr := os.WriteFile(path, zeroed, 0o600); werr != nil {
			return werr
		}
	}
	return os.Remove(path)
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	return nonce, err
}

func Fingerprint(key []byte, value []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return hex.EncodeToString(mac.Sum(nil))
}

func (v *Vault) FingerprintKey(projectID string) ([]byte, error) {
	return v.keyring.GetOrCreate("fingerprint-" + projectID)
}
