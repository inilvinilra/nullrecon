package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	full := append([]string{"--data-dir", dir, "--json"}, args...)
	code := run(full, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestInitProjectScopeFlow(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runCLI(t, dir, "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	code, out, errOut := runCLI(t, dir, "project", "create", "--name", "Acme", "--slug", "acme")
	if code != 0 {
		t.Fatalf("project create: %s", errOut)
	}
	var project map[string]any
	if err := json.Unmarshal([]byte(out), &project); err != nil {
		t.Fatal(err)
	}
	if project["slug"] != "acme" {
		t.Fatalf("unexpected project: %s", out)
	}
	code, out2, _ := runCLI(t, dir, "project", "create", "--name", "Acme", "--slug", "acme")
	if code != 0 {
		t.Fatal("project create must be idempotent")
	}
	var again map[string]any
	json.Unmarshal([]byte(out2), &again)
	if again["id"] != project["id"] {
		t.Fatal("idempotent create must return the same project")
	}

	scopeFile := filepath.Join(dir, "scope.json")
	scope := `{"kind":"scope","version":"nr.scope/v1","rootDomains":["example.com"],"ports":[443],"protocols":["tcp"]}`
	if err := os.WriteFile(scopeFile, []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, dir, "scope", "validate", "--file", scopeFile); code != 0 {
		t.Fatalf("scope validate: %s", errOut)
	}
	if code, _, errOut := runCLI(t, dir, "scope", "import", "--project", "acme", "--label", "default", "--file", scopeFile); code != 0 {
		t.Fatalf("scope import: %s", errOut)
	}

	code, out3, _ := runCLI(t, dir, "scope", "explain", "--project", "acme", "--label", "default", "--mode", "safeactive", "--host", "www.example.com", "--port", "443")
	if code != 0 {
		t.Fatal("explain must succeed")
	}
	var decision map[string]any
	json.Unmarshal([]byte(out3), &decision)
	if decision["allowed"] != false {
		t.Fatalf("explain must fail closed without a stored authorization: %s", out3)
	}
}

func TestExplainRejectsOutOfScope(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, dir, "init")
	runCLI(t, dir, "project", "create", "--name", "Acme", "--slug", "acme")
	scopeFile := filepath.Join(dir, "scope.json")
	os.WriteFile(scopeFile, []byte(`{"kind":"scope","version":"nr.scope/v1","rootDomains":["example.com"],"ports":[443]}`), 0o600)
	runCLI(t, dir, "scope", "import", "--project", "acme", "--label", "default", "--file", scopeFile)
	code, out, _ := runCLI(t, dir, "scope", "explain", "--project", "acme", "--label", "default", "--mode", "safeactive", "--host", "other.net", "--port", "443")
	if code != 0 {
		t.Fatal("explain itself must succeed")
	}
	if !strings.Contains(out, "no valid authorization") {
		t.Fatalf("expected fail-closed authorization reason, got %s", out)
	}
}

func TestProviderList(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, dir, "init")
	code, out, _ := runCLI(t, dir, "provider", "list")
	if code != 0 {
		t.Fatal("provider list must succeed")
	}
	for _, name := range []string{"fofa", "censys", "netlas", "shodan", "leakix"} {
		if !strings.Contains(out, name) {
			t.Fatalf("provider %s missing from list: %s", name, out)
		}
	}
}

func TestUsageOnUnknownCommand(t *testing.T) {
	dir := t.TempDir()
	code, _, errOut := runCLI(t, dir, "frobnicate")
	if code != exitUsage {
		t.Fatalf("unknown command must exit %d, got %d", exitUsage, code)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Fatal("unknown command must report usage")
	}
}

func TestScopeValidateRejectsBadScope(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, dir, "init")
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"kind":"scope","version":"nr.scope/v1","cidrs":["not-a-cidr"]}`), 0o600)
	code, _, _ := runCLI(t, dir, "scope", "validate", "--file", bad)
	if code == 0 {
		t.Fatal("invalid scope must fail validation")
	}
}
