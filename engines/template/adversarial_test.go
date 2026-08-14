package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdversarialTargetPrecisionRecall(t *testing.T) {
	planted := map[string]string{
		"/.git/config":             "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://x/y.git\n",
		"/webmail/logs/errors.log": "[11-Nov-2020 11:05:05 +0000]: <abc> IMAP Error: Login failed for user@example.com\n",
		"/phpinfo.php":             "<html><head><title>phpinfo()</title></head><body>PHP Version 7.4.3</body></html>",
		"/server-status":           "<html><body><h1>Apache Server Status</h1>Total Traffic: 1MB<br>Server uptime: 1 day</body></html>",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := planted[r.URL.Path]; ok {
			w.WriteHeader(200)
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<!doctype html><html><head><title>Welcome</title></head><body><h1>It works</h1><p>You requested " + r.URL.Path + " but this is a soft-404 catch-all.</p></body></html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	matched := map[string]bool{}
	for _, m := range res.Matches {
		matched[m.TemplateID] = true
		if m.TemplateID == "server-version-disclosure" {
			continue
		}
		u := m.URL[len(srv.URL):]
		if _, isPlanted := planted[u]; !isPlanted {
			t.Fatalf("FALSE POSITIVE: template %q matched non-planted path %q on a soft-404 responder", m.TemplateID, u)
		}
	}
	wantRecall := []string{"git-config-exposure", "roundcube-log-disclosure", "phpinfo-exposure", "server-status-exposure"}
	missed := []string{}
	for _, id := range wantRecall {
		if !matched[id] {
			missed = append(missed, id)
		}
	}
	if len(missed) > 0 {
		t.Fatalf("RECALL miss on planted vulns: %v (soft-404 must not mask real content-verified findings)", missed)
	}
	t.Logf("adversarial target: %d/%d planted vulns detected, zero false positives against soft-404 catch-all", len(wantRecall)-len(missed), len(wantRecall))
}
