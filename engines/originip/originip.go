package originip

import (
	"context"
	"crypto/tls"
	"io"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/fingerprint"
)

type ClassifiedIP struct {
	IP        string `json:"ip"`
	Provider  string `json:"provider,omitempty"`
	Protected bool   `json:"protected"`
	Candidate bool   `json:"candidate"`
}

type OriginCandidate struct {
	IP           string   `json:"ip"`
	State        string   `json:"state"`
	Confidence   float64  `json:"confidence"`
	Reasons      []string `json:"reasons,omitempty"`
	Status       int      `json:"status,omitempty"`
	Title        string   `json:"title,omitempty"`
	Probed       bool     `json:"probed"`
	ScopeBlocked bool     `json:"scopeBlocked,omitempty"`
}

type Result struct {
	Domain    string            `json:"domain"`
	Reference Reference         `json:"reference"`
	Protected []ClassifiedIP    `json:"protected,omitempty"`
	Origins   []OriginCandidate `json:"origins"`
	Requested int               `json:"requested"`
	Blocked   int               `json:"blocked"`
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	nm       *NetworkMap
	client   *http.Client
	timeout  time.Duration
	maxBody  int64
	now      func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard, nm *NetworkMap) *Engine {
	timeout := 8 * time.Second
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		nm:       nm,
		timeout:  timeout,
		maxBody:  8192,
		now:      func() time.Time { return time.Now().UTC() },
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (e *Engine) Classify(ips []string) []ClassifiedIP {
	seen := map[string]bool{}
	var out []ClassifiedIP
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		provider, protected := e.nm.Classify(ip)
		ci := ClassifiedIP{IP: ip, Provider: provider, Protected: protected}
		if !protected && isPublicIP(ip) {
			ci.Candidate = true
		}
		out = append(out, ci)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (e *Engine) Scan(ctx context.Context, domain string, ips []string) (Result, error) {
	res := Result{Domain: domain, Origins: []OriginCandidate{}}
	classified := e.Classify(ips)
	var candidates []string
	for _, c := range classified {
		switch {
		case c.Protected:
			res.Protected = append(res.Protected, c)
		case c.Candidate:
			candidates = append(candidates, c.IP)
		}
	}
	if len(candidates) == 0 {
		return res, nil
	}
	ref := e.fetchReference(ctx, domain)
	res.Reference = ref
	if ref.Error != "" {
		for _, ip := range candidates {
			res.Origins = append(res.Origins, OriginCandidate{IP: ip, State: "needsreview"})
		}
		return res, nil
	}
	origins, requested, blocked := e.verify(ctx, domain, ref, candidates)
	res.Origins = origins
	res.Requested = requested
	res.Blocked = blocked
	return res, nil
}

func (e *Engine) fetchReference(ctx context.Context, domain string) Reference {
	ref := Reference{}
	if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: domain, Path: "/"}, "httpget", e.now()); !d.Allowed {
		ref.Error = "reference domain out of scope"
		return ref
	}
	if !e.acquire(ctx) {
		ref.Error = "budget exhausted"
		return ref
	}
	status, title, bodyHash, err := e.fetch(ctx, "https://"+domain+"/", domain)
	if err != nil {
		ref.Error = err.Error()
		return ref
	}
	ref.Status = status
	ref.Title = title
	ref.BodyHash = bodyHash
	if e.acquire(ctx) {
		ref.FaviconMMH3 = e.favicon(ctx, "https://"+domain+"/favicon.ico", domain)
	}
	return ref
}

func (e *Engine) verify(ctx context.Context, domain string, ref Reference, candidates []string) ([]OriginCandidate, int, int) {
	var out []OriginCandidate
	requested := 0
	blocked := 0
	for _, ip := range candidates {
		oc := OriginCandidate{IP: ip}
		if d := e.snapshot.EvaluateAction(scopeguard.Target{IP: ip, Path: "/"}, "httpget", e.now()); !d.Allowed {
			oc.State = "needsreview"
			oc.ScopeBlocked = true
			blocked++
			out = append(out, oc)
			continue
		}
		if !e.acquire(ctx) {
			oc.State = "needsreview"
			blocked++
			out = append(out, oc)
			continue
		}
		requested++
		status, title, bodyHash, err := e.fetch(ctx, "https://"+ip+"/", domain)
		if err != nil {
			continue
		}
		var fav *int32
		if ref.FaviconMMH3 != nil && e.acquire(ctx) {
			requested++
			fav = e.favicon(ctx, "https://"+ip+"/favicon.ico", domain)
		}
		score, reasons := compare(probeResult{Status: status, Title: title, BodyHash: bodyHash, FaviconMMH3: fav}, ref)
		if score > 1 {
			score = 1
		}
		state := matchState(score, reasons)
		if state == "rejected" {
			continue
		}
		oc.Probed = true
		oc.Status = status
		oc.Title = title
		oc.Confidence = math.Round(score*100) / 100
		oc.Reasons = reasons
		oc.State = state
		out = append(out, oc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out, requested, blocked
}

func (e *Engine) acquire(ctx context.Context) bool {
	if e.budget == nil {
		return true
	}
	return e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}) == nil
}

func (e *Engine) fetch(ctx context.Context, url, host string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Host = host
	req.Header.Set("User-Agent", "nullrecon/0.1")
	req.Header.Set("Accept", "*/*")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, e.maxBody))
	return resp.StatusCode, extractTitle(body), hashBody(body), nil
}

func (e *Engine) favicon(ctx context.Context, url, host string) *int32 {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Host = host
	req.Header.Set("User-Agent", "nullrecon/0.1")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(data) == 0 {
		return nil
	}
	h := fingerprint.FaviconMMH3(data)
	return &h
}
