package template

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/engines/oob"
)

func ssrfTarget(callbackReached *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" {
			if u := r.URL.Query().Get("url"); u != "" {
				resp, err := http.Get(u)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if callbackReached != nil {
						*callbackReached = true
					}
				}
			}
			w.WriteHeader(200)
			w.Write([]byte("fetched"))
			return
		}
		w.WriteHeader(404)
	}))
}

func oobTemplate() *Set {
	set, _ := Parse([]byte(`{"templates":[{
	  "id":"blind-ssrf-oob","info":{"name":"Blind SSRF via OOB","severity":"high","cve":"CVE-9999-1000"},
	  "requests":[{"method":"GET","path":["/fetch?url=http://{{interactsh-url}}"],"matchersCondition":"and",
	    "matchers":[{"type":"status","status":[200]},{"type":"word","part":"interactsh_protocol","words":["http"]}]}]}]}`))
	return set
}

func TestOOBConfirmsBlindSSRF(t *testing.T) {
	it, err := oob.NewInteractor("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	srv := ssrfTarget(nil)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	engine := New(testSnapshot(t, host, port), nil).WithInteractor(it)
	res, err := engine.Run(context.Background(), srv.URL, oobTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("blind SSRF must be confirmed by an OOB callback, got %d matches", len(res.Matches))
	}
}

func TestOOBNoCallbackNoFinding(t *testing.T) {
	it, err := oob.NewInteractor("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("no ssrf here"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	engine := New(testSnapshot(t, host, port), nil).WithInteractor(it)
	engine.oobWait = 300 * time.Millisecond
	res, err := engine.Run(context.Background(), srv.URL, oobTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("without an OOB callback the blind template must not confirm, got %d", len(res.Matches))
	}
}

func TestOOBSkippedWithoutInteractor(t *testing.T) {
	srv := ssrfTarget(nil)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	engine := New(testSnapshot(t, host, port), nil)
	res, err := engine.Run(context.Background(), srv.URL, oobTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("OOB template must be skipped when no interactor is configured, got %d", len(res.Matches))
	}
}
