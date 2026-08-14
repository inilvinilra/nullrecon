package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMultiRequestChaining(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.WriteHeader(200)
			w.Write([]byte(`<html><input name="csrf" value="TOK-a1b2c3d4"></html>`))
		case "/step2":
			if r.URL.Query().Get("t") == "TOK-a1b2c3d4" {
				w.WriteHeader(200)
				w.Write([]byte(`{"result":"admin-created","status":"vulnerable-confirmed"}`))
				return
			}
			w.WriteHeader(403)
			w.Write([]byte(`forbidden`))
		default:
			w.WriteHeader(200)
			w.Write([]byte("soft-404"))
		}
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	set, err := Parse([]byte(`{"templates":[{
	  "id":"chain-probe","info":{"name":"chained","severity":"critical","cve":"CVE-9999-0003"},
	  "requests":[
	    {"method":"GET","path":["/step1"],
	     "extractors":[{"type":"regex","part":"body","name":"token","regex":["value=\"(TOK-[a-z0-9]+)\""],"group":1}],
	     "matchers":[{"type":"status","status":[200]}]},
	    {"method":"GET","path":["/step2?t={{token}}"],"matchersCondition":"and",
	     "matchers":[{"type":"status","status":[200]},{"type":"word","part":"body","words":["vulnerable-confirmed"]}]}
	  ]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("chained template must confirm via extracted token, got %d matches (requested=%d)", len(res.Matches), res.Requested)
	}
	if res.Matches[0].Status != 200 {
		t.Fatalf("finding must reflect the final step response, got status %d", res.Matches[0].Status)
	}
}

func TestMultiRequestChainRejectsWhenTokenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/step2" && r.URL.Query().Get("t") == "TOK-a1b2c3d4" {
			w.WriteHeader(200)
			w.Write([]byte("vulnerable-confirmed"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>no token here</html>"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, _ := Parse([]byte(`{"templates":[{
	  "id":"chain-probe2","info":{"name":"chained","severity":"critical","cve":"CVE-9999-0004"},
	  "requests":[
	    {"method":"GET","path":["/step1"],
	     "extractors":[{"type":"regex","part":"body","name":"token","regex":["value=\"(TOK-[a-z0-9]+)\""],"group":1}],
	     "matchers":[{"type":"status","status":[200]}]},
	    {"method":"GET","path":["/step2?t={{token}}"],"matchersCondition":"and",
	     "matchers":[{"type":"status","status":[200]},{"type":"word","part":"body","words":["vulnerable-confirmed"]}]}
	  ]}]}`))
	res, _ := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, set)
	if len(res.Matches) != 0 {
		t.Fatalf("without an extractable token the chain must not confirm, got %d", len(res.Matches))
	}
}

func TestMultiRequestCarriesSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "authed-xyz", Path: "/"})
			w.WriteHeader(302)
			w.Write([]byte("redirecting"))
		case "/admin":
			if c, err := r.Cookie("SESSION"); err == nil && c.Value == "authed-xyz" {
				w.WriteHeader(200)
				w.Write([]byte(`<html>admin dashboard: session-confirmed</html>`))
				return
			}
			w.WriteHeader(401)
			w.Write([]byte("unauthorized"))
		default:
			w.WriteHeader(200)
			w.Write([]byte("soft-404"))
		}
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	set, err := Parse([]byte(`{"templates":[{
	  "id":"session-chain","info":{"name":"login then action","severity":"high","cve":"CVE-9999-0005"},
	  "requests":[
	    {"method":"POST","path":["/login"],"body":"user=admin&pass=admin","matchers":[{"type":"status","status":[302]}]},
	    {"method":"GET","path":["/admin"],"matchersCondition":"and","matchers":[{"type":"status","status":[200]},{"type":"word","part":"body","words":["session-confirmed"]}]}
	  ]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := New(testSnapshot(t, host, port), nil).Run(context.Background(), srv.URL, set)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("session cookie from login must be carried to the authenticated action, got %d matches", len(res.Matches))
	}
}
