package objectstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nullrecon/nullrecon/contracts"
)

var ErrNotFound = errors.New("objectstore: object not found")

type Store struct {
	dir string
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(ref string) (string, error) {
	for _, r := range ref {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", fmt.Errorf("objectstore: invalid ref %q", ref)
		}
	}
	if len(ref) != 64 {
		return "", fmt.Errorf("objectstore: invalid ref length")
	}
	return filepath.Join(s.dir, ref[:2], ref[2:]), nil
}

func (s *Store) Put(data []byte) (string, error) {
	ref := contracts.HashBytes(data)
	path, err := s.path(ref)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return ref, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return ref, nil
}

func (s *Store) Get(ref string) ([]byte, error) {
	path, err := s.path(ref)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if contracts.HashBytes(data) != ref {
		return nil, fmt.Errorf("objectstore: integrity check failed for %s", ref)
	}
	return data, nil
}

func (s *Store) Delete(ref string) error {
	path, err := s.path(ref)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		zeroed := make([]byte, len(data))
		if werr := os.WriteFile(path, zeroed, 0o600); werr != nil {
			return werr
		}
	}
	return os.Remove(path)
}
