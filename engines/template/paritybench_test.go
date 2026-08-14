package template

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func vulnMux() http.Handler {
	planted := map[string]struct {
		status  int
		ctype   string
		body    string
		headers map[string]string
	}{
		"/.git/config":      {200, "text/plain", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/acme/secret.git\n", nil},
		"/.git/HEAD":        {200, "text/plain", "ref: refs/heads/master\n", nil},
		"/.env":             {200, "text/plain", "APP_ENV=production\nDB_PASSWORD=s3cr3t\nAPP_KEY=base64:abcdef==\nDB_HOST=127.0.0.1\n", nil},
		"/server-status":    {200, "text/html", "<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for localhost</h1>Server Version: Apache/2.4.49<dt>Server uptime:</dt></body></html>", nil},
		"/server-info":      {200, "text/html", "<html><head><title>Server Information</title></head><body><h1>Apache Server Information</h1>Server Settings, Server Version: Apache</body></html>", nil},
		"/actuator/env":     {200, "application/json", "{\"activeProfiles\":[],\"propertySources\":[{\"name\":\"systemProperties\",\"properties\":{\"java.version\":{\"value\":\"11\"}}}]}", nil},
		"/actuator/health":  {200, "application/json", "{\"status\":\"UP\"}", nil},
		"/.svn/entries":     {200, "text/plain", "10\n\ndir\n", nil},
		"/.DS_Store":        {200, "application/octet-stream", "\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00", nil},
		"/phpinfo.php":      {200, "text/html", "<html><head><title>phpinfo()</title></head><body><h1 class=\"p\">PHP Version 7.4.3</h1><table><tr><td>System</td></tr><tr><td>PHP API</td></tr></table></body></html>", nil},
		"/info.php":         {200, "text/html", "<title>phpinfo()</title><h1 class=\"p\">PHP Version 7.4.3</h1>", nil},
		"/wp-login.php":     {200, "text/html", "<html><head><title>Log In &lsaquo; WordPress</title></head><body class=\"login\"><form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\"><input name=\"log\"></form></body></html>", nil},
		"/.aws/credentials": {200, "text/plain", "[default]\naws_access_key_id = AKIA" + "IOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n", nil},
		"/config.json":      {200, "application/json", "{\"apiKey\":\"test\",\"database\":{\"password\":\"admin123\"}}", nil},
		"/.git/logs/HEAD":   {200, "text/plain", "0000000000000000000000000000000000000000 abc123 committer <a@b.c> 0 +0000\n", nil},
		"/swagger-ui.html":  {200, "text/html", "<html><head><title>Swagger UI</title></head><body><div id=\"swagger-ui\"></div><script>window.onload=function(){const ui=SwaggerUIBundle({url:'/v2/api-docs'})}</script></body></html>", nil},
		"/v2/api-docs":      {200, "application/json", "{\"swagger\":\"2.0\",\"info\":{\"title\":\"api\"},\"paths\":{}}", nil},
		"/.travis.yml":      {200, "text/plain", "language: go\nscript: make test\n", nil},
		"/robots.txt":       {200, "text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup\n", nil},
		"/manager/html":     {401, "text/html", "<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1>You are not authorized to view this page. Tomcat</body></html>", map[string]string{"WWW-Authenticate": "Basic realm=\"Tomcat Manager Application\""}},
	}
	soft404 := "<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found.</p></body></html>"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := planted[r.URL.Path]; ok {
			for k, v := range p.headers {
				w.Header().Set(k, v)
			}
			w.Header().Set("Content-Type", p.ctype)
			w.Header().Set("Server", "Apache/2.4.49 (Unix)")
			w.WriteHeader(p.status)
			w.Write([]byte(p.body))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		w.WriteHeader(200)
		w.Write([]byte(soft404))
	})
}

func TestParityAgainstNuclei(t *testing.T) {
	if os.Getenv("NULLRECON_PARITY") == "" {
		t.Skip("set NULLRECON_PARITY=1 to run the nuclei parity benchmark")
	}
	srv := httptest.NewServer(vulnMux())
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	portStr := strconv.Itoa(port)

	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	engine := New(testSnapshot(t, host, port), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := engine.Run(ctx, srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	nrPaths := map[string]bool{}
	nrCVEs := map[string]bool{}
	for _, m := range res.Matches {
		p := m.URL[strings.LastIndex(m.URL, portStr)+len(portStr):]
		nrPaths[p] = true
		if m.CVE != "" {
			nrCVEs[m.CVE] = true
		}
	}
	t.Logf("NULLRECON: %d requests, %d matches on %d distinct paths", res.Requested, len(res.Matches), len(nrPaths))
	for _, m := range res.Matches {
		t.Logf("  [nullrecon] %-45s sev=%-8s cve=%s", m.TemplateID, m.Severity, m.CVE)
	}

	nucleiBin, lerr := exec.LookPath("nuclei")
	if lerr != nil {
		t.Skip("nuclei not on PATH")
	}
	home, _ := os.UserHomeDir()
	args := []string{"-u", srv.URL, "-jsonl", "-silent", "-no-color", "-duc", "-nc",
		"-t", home + "/nuclei-templates/http/exposures/",
		"-t", home + "/nuclei-templates/http/misconfiguration/",
	}
	cmd := exec.CommandContext(ctx, nucleiBin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	nucPaths := map[string]bool{}
	nucIDs := map[string]bool{}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.HasPrefix(bytes.TrimSpace(line), []byte("{")) {
			continue
		}
		var f struct {
			TemplateID    string `json:"template-id"`
			MatchedAt     string `json:"matched-at"`
			MatchedString string `json:"matched-string"`
			Info          struct {
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if json.Unmarshal(line, &f) != nil {
			continue
		}
		nucIDs[f.TemplateID] = true
		if i := strings.LastIndex(f.MatchedAt, portStr); i >= 0 {
			nucPaths[f.MatchedAt[i+len(portStr):]] = true
		}
	}
	t.Logf("NUCLEI: %d matches (%d distinct template ids)", len(nucIDs), len(nucIDs))
	var ids []string
	for id := range nucIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Logf("  [nuclei] %s", id)
	}

	var nucOnly, nrOnly, both []string
	for p := range nucPaths {
		if nrPaths[p] {
			both = append(both, p)
		} else {
			nucOnly = append(nucOnly, p)
		}
	}
	for p := range nrPaths {
		if !nucPaths[p] {
			nrOnly = append(nrOnly, p)
		}
	}
	sort.Strings(both)
	sort.Strings(nucOnly)
	sort.Strings(nrOnly)
	t.Logf("=== PATH-LEVEL PARITY ===")
	t.Logf("BOTH detected (%d): %v", len(both), both)
	t.Logf("NUCLEI-ONLY (%d): %v", len(nucOnly), nucOnly)
	t.Logf("NULLRECON-ONLY (%d): %v", len(nrOnly), nrOnly)
}
