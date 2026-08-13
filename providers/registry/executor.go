package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/budgetguard"
)

type SecretResolver interface {
	Resolve(secretRef string) (string, error)
}

type RawStore interface {
	Put(data []byte) (string, error)
}

type Result struct {
	Records     []Record   `json:"records"`
	Pages       int        `json:"pages"`
	CreditsUsed int64      `json:"creditsUsed"`
	CacheHit    bool       `json:"cacheHit"`
	Provider    string     `json:"provider"`
	Capability  Capability `json:"capability"`
	NextCursor  string     `json:"nextCursor,omitempty"`
}

type cacheEntry struct {
	page      Page
	expiresAt time.Time
}

type circuit struct {
	failures  int
	openUntil time.Time
}

type Executor struct {
	registry *Registry
	resolver SecretResolver
	raw      RawStore
	client   *http.Client
	mu       sync.Mutex
	cache    map[string]cacheEntry
	circuits map[string]*circuit
	budgets  map[string]*budgetguard.Guard
	now      func() time.Time
}

var ErrCircuitOpen = errors.New("registry: provider circuit open")
var ErrCapability = errors.New("registry: capability not supported by provider")
var ErrAuthMissing = errors.New("registry: required provider credential not configured")

func NewExecutor(r *Registry, resolver SecretResolver, raw RawStore) *Executor {
	return &Executor{
		registry: r,
		resolver: resolver,
		raw:      raw,
		client:   &http.Client{},
		cache:    map[string]cacheEntry{},
		circuits: map[string]*circuit{},
		budgets:  map[string]*budgetguard.Guard{},
		now:      time.Now,
	}
}

func (e *Executor) budgetFor(d Descriptor) *budgetguard.Guard {
	e.mu.Lock()
	defer e.mu.Unlock()
	g, ok := e.budgets[d.Name]
	if !ok {
		limits := budgetguard.Budget{}
		if d.RatePerSecond > 0 {
			limits[budgetguard.DimRPS] = int64(d.RatePerSecond)
		}
		g = budgetguard.New("provider:"+d.Name, limits, nil)
		e.budgets[d.Name] = g
	}
	return g
}

func (e *Executor) SetBudget(name string, g *budgetguard.Guard) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.budgets[name] = g
}

func cacheKey(name string, q Query) string {
	parts := []string{name, string(q.Capability), q.Cursor}
	keys := make([]string, 0, len(q.Params))
	for k := range q.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+q.Params[k])
	}
	return contracts.HashBytes([]byte(strings.Join(parts, "|")))
}

func (e *Executor) Execute(ctx context.Context, name string, q Query) (Result, error) {
	adapter, ok := e.registry.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("registry: unknown provider %q", name)
	}
	d := adapter.Describe()
	if !d.Supports(q.Capability) {
		return Result{}, fmt.Errorf("%w: %s cannot %s", ErrCapability, name, q.Capability)
	}
	res := Result{Provider: name, Capability: q.Capability}
	key := cacheKey(name, q)
	e.mu.Lock()
	if entry, hit := e.cache[key]; hit && e.now().Before(entry.expiresAt) {
		e.mu.Unlock()
		res.Records = entry.page.Records
		res.CacheHit = true
		res.Pages = 1
		res.NextCursor = entry.page.NextCursor
		return res, nil
	}
	c := e.circuits[name]
	if c == nil {
		c = &circuit{}
		e.circuits[name] = c
	}
	if e.now().Before(c.openUntil) {
		e.mu.Unlock()
		return Result{}, ErrCircuitOpen
	}
	e.mu.Unlock()

	var secret string
	if d.Auth.Required {
		if e.resolver == nil || d.Auth.SecretRef == "" {
			return Result{}, ErrAuthMissing
		}
		var err error
		secret, err = e.resolver.Resolve(d.Auth.SecretRef)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrAuthMissing, err)
		}
	}
	if err := e.budgetFor(d).Acquire(ctx, budgetguard.Cost{Requests: 1, Credits: d.CreditPerQuery}); err != nil {
		return Result{}, err
	}

	spec, err := adapter.Build(q, secret)
	if err != nil {
		return Result{}, err
	}
	resp, err := e.doWithRetry(ctx, d, spec, secret)
	if err != nil {
		e.recordFailure(name)
		return Result{}, err
	}
	page, err := adapter.Parse(q, resp)
	if err != nil {
		e.recordFailure(name)
		return Result{}, fmt.Errorf("registry: parse %s: %w", name, err)
	}
	e.recordSuccess(name)
	fetched := e.now().UTC()
	for i := range page.Records {
		page.Records[i].FetchedAt = fetched
		page.Records[i].AdapterVersion = d.AdapterVersion
		if page.Records[i].FreshnessClass == "" {
			page.Records[i].FreshnessClass = d.FreshnessClass
		}
	}
	if e.raw != nil && len(resp.Body) > 0 {
		ref, err := e.raw.Put(resp.Body)
		if err != nil {
			return Result{}, err
		}
		for i := range page.Records {
			page.Records[i].RawRef = ref
			page.Records[i].RawHash = ref
		}
	}
	if d.CacheTTLSeconds > 0 {
		e.mu.Lock()
		e.cache[key] = cacheEntry{page: page, expiresAt: e.now().Add(time.Duration(d.CacheTTLSeconds) * time.Second)}
		e.mu.Unlock()
	}
	res.Records = page.Records
	res.CreditsUsed = page.Credits
	res.Pages = 1
	res.NextCursor = page.NextCursor
	return res, nil
}

func (e *Executor) doWithRetry(ctx context.Context, d Descriptor, spec RequestSpec, secret string) (Response, error) {
	attempts := d.Retry.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(d.Retry.BaseDelayMS*(1<<(attempt-1))) * time.Millisecond
			delay += time.Duration(rand.Int63n(int64(delay/2 + 1)))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Response{}, ctx.Err()
			case <-timer.C:
			}
		}
		resp, retryable, err := e.doOnce(ctx, d, spec)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable {
			return Response{}, err
		}
	}
	return Response{}, lastErr
}

func (e *Executor) doOnce(ctx context.Context, d Descriptor, spec RequestSpec) (Response, bool, error) {
	endpoint := strings.TrimRight(d.Endpoint, "/")
	u, err := url.Parse(endpoint + spec.Path)
	if err != nil {
		return Response{}, false, err
	}
	query := u.Query()
	for k, v := range spec.Query {
		query.Set(k, v)
	}
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, spec.Method, u.String(), strings.NewReader(string(spec.Body)))
	if err != nil {
		return Response{}, false, err
	}
	req.Header.Set("User-Agent", "nullrecon/0.1")
	req.Header.Set("Accept", "application/json")
	for k, v := range spec.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return Response{}, true, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Response{}, true, err
	}
	out := Response{Status: resp.StatusCode, Headers: map[string]string{}, Body: body}
	for k := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "retry-after" || strings.HasPrefix(lk, "x-ratelimit") {
			out.Headers[k] = resp.Header.Get(k)
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden || resp.StatusCode >= 500 {
		return out, true, fmt.Errorf("registry: provider %s status %d", d.Name, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return out, false, fmt.Errorf("registry: provider %s status %d", d.Name, resp.StatusCode)
	}
	return out, false, nil
}

func (e *Executor) recordFailure(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.circuits[name]
	c.failures++
	if c.failures >= 5 {
		c.openUntil = e.now().Add(60 * time.Second)
	}
}

func (e *Executor) recordSuccess(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.circuits[name] = &circuit{}
}

func (e *Executor) Healthy(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.circuits[name]
	return c == nil || e.now().After(c.openUntil)
}
