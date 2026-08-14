package template

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/engines/oob"
)

func TestEmbeddedOOBTemplatesConfirmViaCallback(t *testing.T) {
	if os.Getenv("NULLRECON_OOB_E2E") == "" {
		t.Skip("set NULLRECON_OOB_E2E to run the embedded OOB end-to-end scan")
	}
	full, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	oobSet := &Set{}
	for _, tmpl := range full.Templates {
		if templateUsesOOB(tmpl) {
			oobSet.Templates = append(oobSet.Templates, tmpl)
		}
	}
	t.Logf("embedded OOB templates: %d", len(oobSet.Templates))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fields := []string{r.URL.RawQuery}
		for _, vs := range r.Form {
			fields = append(fields, vs...)
		}
		for _, f := range fields {
			for _, marker := range []string{"http://", "https://"} {
				rest := f
				for idx := strings.Index(rest, marker); idx >= 0; idx = strings.Index(rest, marker) {
					end := idx
					for end < len(rest) && rest[end] != '&' && rest[end] != ' ' && rest[end] != '"' {
						end++
					}
					go func(u string) {
						cl := &http.Client{Timeout: 2 * time.Second}
						if resp, e := cl.Get(u); e == nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
					}(rest[idx:end])
					rest = rest[end:]
				}
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	it, err := oob.NewInteractor("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	host, port := hostPort(t, srv.URL)
	engine := New(testSnapshot(t, host, port), nil).WithInteractor(it)
	engine.oobWait = 500 * time.Millisecond
	res, err := engine.Run(context.Background(), srv.URL, oobSet)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OOB-confirmed findings: %d of %d templates", len(res.Matches), len(oobSet.Templates))
	for i, m := range res.Matches {
		if i >= 15 {
			break
		}
		t.Logf("  confirmed %s (%s)", m.TemplateID, m.CVE)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected at least one embedded OOB template to confirm via a query-based SSRF callback")
	}
}
