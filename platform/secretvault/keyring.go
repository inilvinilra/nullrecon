package secretvault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrKeyNotFound = errors.New("secretvault: key not found")

type Keyring interface {
	Get(keyID string) ([]byte, error)
	Put(keyID string, key []byte) error
}

type FileKeyring struct {
	dir string
}

func NewFileKeyring(dir string) (*FileKeyring, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileKeyring{dir: dir}, nil
}

func (k *FileKeyring) path(keyID string) (string, error) {
	for _, r := range keyID {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return "", fmt.Errorf("secretvault: invalid key id %q", keyID)
		}
	}
	return filepath.Join(k.dir, keyID+".key"), nil
}

func (k *FileKeyring) Get(keyID string) ([]byte, error) {
	path, err := k.path(keyID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("secretvault: corrupt key %q", keyID)
	}
	return data, nil
}

func (k *FileKeyring) Put(keyID string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("secretvault: keys must be 32 bytes")
	}
	path, err := k.path(keyID)
	if err != nil {
		return err
	}
	return os.WriteFile(path, key, 0o600)
}

func (k *FileKeyring) GetOrCreate(keyID string) ([]byte, error) {
	key, err := k.Get(keyID)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := k.Put(keyID, key); err != nil {
		return nil, err
	}
	return key, nil
}
