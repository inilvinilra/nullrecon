package contentdiscovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Options struct {
	Words           []string
	Extensions      []string
	MatchStatus     map[int]bool
	Concurrency     int
	CalibrateProbes int
	FilterSizes     map[int64]bool
}

type Hit struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
	Words       int    `json:"words"`
	Lines       int    `json:"lines"`
	ContentType string `json:"contentType,omitempty"`
	Redirect    string `json:"redirect,omitempty"`
	BodyHash    string `json:"bodyHash,omitempty"`
	Class       string `json:"class"`
}

type Result struct {
	Target    string   `json:"target"`
	Baseline  Baseline `json:"baseline"`
	Hits      []Hit    `json:"hits"`
	Requested int      `json:"requested"`
	Blocked   int      `json:"blocked"`
	Errors    []string `json:"errors,omitempty"`
}

type Engine struct {
	snapshot    scopeguard.Snapshot
	budget      *budgetguard.Guard
	client      *http.Client
	maxBody     int64
	timeout     time.Duration
	concurrency int
	userAgent   string
	now         func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	timeout := 10 * time.Second
	return &Engine{
		snapshot:    snapshot,
		budget:      budget,
		maxBody:     64 << 10,
		timeout:     timeout,
		concurrency: 16,
		userAgent:   "nullrecon/0.1",
		now:         func() time.Time { return time.Now().UTC() },
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

type probe struct {
	status      int
	length      int64
	words       int
	lines       int
	contentType string
	location    string
	bodyHash    string
}

func (e *Engine) Scan(ctx context.Context, target string, opt Options) (Result, error) {
	base, err := url.Parse(strings.TrimRight(target, "/"))
	if err != nil {
		return Result{}, fmt.Errorf("contentdiscovery: invalid target: %w", err)
	}
	res := Result{Target: base.String()}
	baseline, calReq, calErr := e.calibrate(ctx, base, opt)
	res.Baseline = baseline
	res.Requested += calReq
	if calErr != nil {
		res.Errors = append(res.Errors, "calibrate: "+calErr.Error())
	}
	paths := buildPaths(opt.Words, opt.Extensions)
	match := opt.MatchStatus
	if match == nil {
		match = defaultMatchStatus()
	}
	concurrency := opt.Concurrency
	if concurrency <= 0 {
		concurrency = e.concurrency
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
		hits []Hit
	)
	for _, path := range paths {
		full := base.String() + "/" + path
		parsed, perr := url.Parse(full)
		if perr != nil {
			continue
		}
		if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path}, "httpget", e.now()); !d.Allowed {
			mu.Lock()
			res.Blocked++
			mu.Unlock()
			continue
		}
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
				mu.Lock()
				res.Blocked++
				mu.Unlock()
				continue
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(path, full string) {
			defer wg.Done()
			defer func() { <-sem }()
			pr, err := e.request(ctx, full)
			mu.Lock()
			res.Requested++
			if err != nil {
				res.Errors = append(res.Errors, path+": "+err.Error())
				mu.Unlock()
				return
			}
			mu.Unlock()
			if !match[pr.status] {
				return
			}
			hit := Hit{
				Path:        path,
				URL:         full,
				Status:      pr.status,
				Length:      pr.length,
				Words:       pr.words,
				Lines:       pr.lines,
				ContentType: pr.contentType,
				Redirect:    pr.location,
				BodyHash:    pr.bodyHash,
			}
			mu.Lock()
			hits = append(hits, hit)
			mu.Unlock()
		}(path, full)
	}
	wg.Wait()
	res.Hits = classify(hits, baseline, opt.FilterSizes)
	return res, nil
}

func (e *Engine) request(ctx context.Context, full string) (probe, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return probe{}, err
	}
	req.Header.Set("User-Agent", e.userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := e.client.Do(req)
	if err != nil {
		return probe{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, e.maxBody))
	sum := sha256.Sum256(body)
	pr := probe{
		status:      resp.StatusCode,
		length:      int64(len(body)),
		words:       countWords(body),
		lines:       countLines(body),
		contentType: normalizeContentType(resp.Header.Get("Content-Type")),
		location:    strings.TrimSpace(resp.Header.Get("Location")),
		bodyHash:    hex.EncodeToString(sum[:]),
	}
	return pr, nil
}

func buildPaths(words, extensions []string) []string {
	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimLeft(strings.TrimSpace(p), "/")
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		add(word)
		for _, ext := range extensions {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			add(word + ext)
		}
	}
	return paths
}

func defaultMatchStatus() map[int]bool {
	return map[int]bool{200: true, 204: true, 301: true, 302: true, 307: true, 401: true, 403: true, 405: true}
}

func normalizeContentType(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func countWords(body []byte) int {
	return len(strings.Fields(string(body)))
}

func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	return strings.Count(string(body), "\n") + 1
}
