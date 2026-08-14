package secretscan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestSecretParityCorpus(t *testing.T) {
	dir := os.Getenv("NULLRECON_SECRET_DIR")
	if dir == "" {
		t.Skip("set NULLRECON_SECRET_DIR to run the gitleaks parity corpus")
	}
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) == ".git" || filepath.Base(path) == ".git" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		res := Scan(set, data, path)
		for _, c := range res.Candidates {
			found[c.DetectorID] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Logf("NULLRECON secretscan detected %d distinct types: %v", len(ids), ids)
}
