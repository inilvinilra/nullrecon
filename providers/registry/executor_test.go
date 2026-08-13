package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAdapter struct {
	endpoint string
	name     string
	caps     []Capability
}

func (f *fakeAdapter) Describe() Descriptor {
	d := NewDescriptor(f.name, "1.0.0", f.endpoint, f.caps)
	d.Retry = RetryPolicy{MaxAttempts: 3, BaseDelayMS: 1}
	d.CacheTTLSeconds = 60
	return d
}

func (f *fakeAdapter) Build(q Query, secret string) (RequestSpec, error) {
	return RequestSpec{Method: "GET", Path: "/query", Query: map[string]string{"q": q.Params["q"]}}, nil
}

func (f *fakeAdapter) Parse(q Query, resp Response) (Page, error) {
	return Page{Records: []Record{{Kind: "host", Value: q.Params["q"]}}, Credits: 1}, nil
}

type fakeResolver struct{}

func (fakeResolver) Resolve(ref string) (string, error) { return "secret", nil }

type memRawStore struct {
	count atomic.Int32
}

func (m *memRawStore) Put(data []byte) (string, error) {
	m.count.Add(1)
	return "rawref", nil
}

func setup(t *testing.T, handler http.HandlerFunc) (*Executor, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	reg := New()
	reg.Register(&fakeAdapter{endpoint: srv.URL, name: "fake", caps: []Capability{CapHostLookup}})
	return NewExecutor(reg, fakeResolver{}, nil), &calls
}

func TestExecuteHappyPath(t *testing.T) {
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}
	e, calls := setup(t, okHandler)
	res, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0].Value != "1.2.3.4" {
		t.Fatalf("bad result: %+v", res)
	}
	if res.Records[0].FetchedAt.IsZero() {
		t.Fatal("executor must stamp fetchedAt")
	}
	res2, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.CacheHit {
		t.Fatal("second identical query must hit cache")
	}
	if calls.Load() != 1 {
		t.Fatalf("cache must prevent second HTTP call, got %d", calls.Load())
	}
}

func TestUnsupportedCapability(t *testing.T) {
	e, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {})
	_, err := e.Execute(context.Background(), "fake", Query{Capability: CapLeakSearch})
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected capability error, got %v", err)
	}
}

func TestRetryOnServerError(t *testing.T) {
	var attempts atomic.Int32
	e, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	res, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatal("retry must recover")
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts.Load())
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	e, calls := setup(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	_, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "x"}})
	if err == nil {
		t.Fatal("400 must fail")
	}
	if calls.Load() != 1 {
		t.Fatalf("400 must not be retried, got %d calls", calls.Load())
	}
}

func TestCircuitBreakerOpens(t *testing.T) {
	e, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	opened := false
	for i := 0; i < 6; i++ {
		_, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": fmt.Sprintf("q%d", i)}})
		if errors.Is(err, ErrCircuitOpen) {
			opened = true
			break
		}
	}
	if !opened || e.Healthy("fake") {
		t.Fatal("circuit must open after repeated failures")
	}
}

func TestCancellation(t *testing.T) {
	e, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{}`))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := e.Execute(ctx, "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "x"}}); err == nil {
		t.Fatal("cancelled context must abort execution")
	}
}

func TestRawArtifactStored(t *testing.T) {
	e, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	raw := &memRawStore{}
	e.raw = raw
	res, err := e.Execute(context.Background(), "fake", Query{Capability: CapHostLookup, Params: map[string]string{"q": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if raw.count.Load() != 1 {
		t.Fatal("raw response body must be stored")
	}
	if res.Records[0].RawRef != "rawref" {
		t.Fatal("records must reference the raw artifact")
	}
}

func TestAuthRequiredMissingResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer srv.Close()
	reg := New()
	reg.Register(&authAdapter{endpoint: srv.URL})
	e := NewExecutor(reg, nil, nil)
	if _, err := e.Execute(context.Background(), "authy", Query{Capability: CapHostLookup, Params: map[string]string{"q": "x"}}); !errors.Is(err, ErrAuthMissing) {
		t.Fatalf("missing credentials must fail closed, got %v", err)
	}
}

type authAdapter struct {
	endpoint string
}

func (a *authAdapter) Describe() Descriptor {
	d := NewDescriptor("authy", "1.0.0", a.endpoint, []Capability{CapHostLookup})
	d.Auth = AuthSpec{Kind: AuthHeader, Header: "X-Key", SecretRef: "provider/authy", Required: true}
	return d
}

func (a *authAdapter) Build(q Query, secret string) (RequestSpec, error) {
	return RequestSpec{Method: "GET", Path: "/"}, nil
}

func (a *authAdapter) Parse(q Query, resp Response) (Page, error) {
	return Page{}, nil
}
