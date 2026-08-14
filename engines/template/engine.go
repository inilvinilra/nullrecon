package template

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/oob"
)

type Match struct {
	TemplateID   string              `json:"templateId"`
	Name         string              `json:"name"`
	Severity     string              `json:"severity"`
	CVE          string              `json:"cve,omitempty"`
	CWE          string              `json:"cwe,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Prerequisite bool                `json:"prerequisite"`
	URL          string              `json:"url"`
	Method       string              `json:"method"`
	Status       int                 `json:"status"`
	ContentHash  string              `json:"contentHash"`
	Extracted    map[string][]string `json:"extracted,omitempty"`
}

type Result struct {
	Target    string   `json:"target"`
	Matches   []Match  `json:"matches"`
	Requested int      `json:"requested"`
	Blocked   int      `json:"blocked"`
	Errors    []string `json:"errors,omitempty"`
}

type Engine struct {
	snapshot   scopeguard.Snapshot
	budget     *budgetguard.Guard
	client     *http.Client
	maxBody    int64
	now        func() time.Time
	interactor Interactor
	oobWait    time.Duration
}

type Interactor interface {
	NewSession() (token, callbackURL string)
	Poll(token string) []oob.Interaction
}

func (e *Engine) WithInteractor(it Interactor) *Engine {
	e.interactor = it
	if e.oobWait == 0 {
		e.oobWait = 3 * time.Second
	}
	return e
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	timeout := 10 * time.Second
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		maxBody:  512 << 10,
		now:      func() time.Time { return time.Now().UTC() },
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (e *Engine) Run(ctx context.Context, target string, set *Set) (Result, error) {
	base, err := url.Parse(strings.TrimRight(target, "/"))
	if err != nil || base.Host == "" {
		return Result{}, fmt.Errorf("template: invalid target %q", target)
	}
	res := Result{Target: base.String()}
	for _, tmpl := range set.Templates {
		if templateUsesOOB(tmpl) {
			if e.interactor != nil {
				e.runOOB(ctx, base, tmpl, &res)
			}
			continue
		}
		if len(tmpl.Requests) > 1 {
			e.runChained(ctx, base, tmpl, &res)
			continue
		}
		for _, req := range tmpl.Requests {
			for _, path := range req.Paths {
				full := base.String() + "/" + strings.TrimLeft(path, "/")
				parsed, perr := url.Parse(full)
				if perr != nil {
					continue
				}
				target := scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path, Protocol: "tcp", Port: portOfURL(parsed)}
				if d := e.snapshot.EvaluateAction(target, "httpget", e.now()); !d.Allowed {
					res.Blocked++
					continue
				}
				if e.budget != nil {
					if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
						res.Blocked++
						continue
					}
				}
				res.Requested++
				status, body, headers, err := e.fetch(ctx, req, full)
				if err != nil {
					res.Errors = append(res.Errors, tmpl.ID+": "+err.Error())
					continue
				}
				view := newResponseView(status, body, headers)
				if !req.matches(view) {
					continue
				}
				if tmpl.Info.Reflection && !e.reflectionConfirmed(ctx, req, full) {
					continue
				}
				sum := sha256.Sum256(body)
				res.Matches = append(res.Matches, Match{
					TemplateID:   tmpl.ID,
					Name:         tmpl.Info.Name,
					Severity:     tmpl.Info.Severity,
					CVE:          tmpl.Info.CVE,
					CWE:          tmpl.Info.CWE,
					Tags:         tmpl.Info.Tags,
					Prerequisite: tmpl.Info.Prerequisite,
					URL:          full,
					Method:       req.Method,
					Status:       status,
					ContentHash:  hex.EncodeToString(sum[:]),
					Extracted:    req.extract(view),
				})
			}
		}
	}
	return res, nil
}

func templateUsesOOB(tmpl Template) bool {
	for _, req := range tmpl.Requests {
		for _, p := range req.Paths {
			if strings.Contains(p, "{{interactsh-url}}") {
				return true
			}
		}
		if strings.Contains(req.Body, "{{interactsh-url}}") {
			return true
		}
		for _, v := range req.Headers {
			if strings.Contains(v, "{{interactsh-url}}") {
				return true
			}
		}
	}
	return false
}

func substOOB(s, callbackURL string) string {
	if !strings.Contains(s, "{{interactsh-url}}") {
		return s
	}
	return strings.ReplaceAll(s, "{{interactsh-url}}", callbackURL)
}

func (e *Engine) runOOB(ctx context.Context, base *url.URL, tmpl Template, res *Result) {
	token, callbackURL := e.interactor.NewSession()
	client := e.chainClient()
	vars := map[string]string{}
	var lastFull string
	var lastStatus int
	var lastBody []byte
	var lastHeaders map[string]string
	for _, req := range tmpl.Requests {
		path := "/"
		if len(req.Paths) > 0 {
			path = req.Paths[0]
		}
		path = substOOB(substChainVars(path, vars), callbackURL)
		full := base.String() + "/" + strings.TrimLeft(path, "/")
		parsed, perr := url.Parse(full)
		if perr != nil {
			return
		}
		tgt := scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path, Protocol: "tcp", Port: portOfURL(parsed)}
		if d := e.snapshot.EvaluateAction(tgt, "httpget", e.now()); !d.Allowed {
			res.Blocked++
			return
		}
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
				res.Blocked++
				return
			}
		}
		res.Requested++
		creq := req
		if len(req.Headers) > 0 {
			h := make(map[string]string, len(req.Headers))
			for k, v := range req.Headers {
				h[k] = substOOB(substChainVars(v, vars), callbackURL)
			}
			creq.Headers = h
		}
		creq.Body = substOOB(substChainVars(req.Body, vars), callbackURL)
		status, body, headers, err := e.fetchVia(ctx, client, creq, full)
		if err != nil {
			res.Errors = append(res.Errors, tmpl.ID+": "+err.Error())
			return
		}
		view := newResponseView(status, body, headers)
		for name, vals := range req.extract(view) {
			if len(vals) > 0 {
				vars[name] = vals[0]
			}
		}
		lastFull, lastStatus, lastBody, lastHeaders = full, status, body, headers
	}
	protocols := e.pollOOB(token)
	view := newResponseView(lastStatus, lastBody, lastHeaders)
	view.oob = protocols
	final := tmpl.Requests[len(tmpl.Requests)-1]
	if !final.matches(view) {
		return
	}
	sum := sha256.Sum256(lastBody)
	res.Matches = append(res.Matches, Match{
		TemplateID:   tmpl.ID,
		Name:         tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		CVE:          tmpl.Info.CVE,
		CWE:          tmpl.Info.CWE,
		Tags:         tmpl.Info.Tags,
		Prerequisite: tmpl.Info.Prerequisite,
		URL:          lastFull,
		Method:       final.Method,
		Status:       lastStatus,
		ContentHash:  hex.EncodeToString(sum[:]),
	})
}

func (e *Engine) pollOOB(token string) string {
	deadline := e.now().Add(e.oobWait)
	for {
		hits := e.interactor.Poll(token)
		if len(hits) > 0 {
			seen := map[string]bool{}
			var protocols []string
			for _, h := range hits {
				if !seen[h.Protocol] {
					seen[h.Protocol] = true
					protocols = append(protocols, h.Protocol)
				}
			}
			return strings.Join(protocols, "\n")
		}
		if !e.now().Before(deadline) {
			return ""
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *Engine) runChained(ctx context.Context, base *url.URL, tmpl Template, res *Result) {
	client := e.chainClient()
	vars := map[string]string{}
	allMatched := true
	hadMatchers := false
	var lastFull string
	var lastStatus int
	var lastBody []byte
	for _, req := range tmpl.Requests {
		path := "/"
		if len(req.Paths) > 0 {
			path = req.Paths[0]
		}
		path = substChainVars(path, vars)
		full := base.String() + "/" + strings.TrimLeft(path, "/")
		parsed, perr := url.Parse(full)
		if perr != nil {
			return
		}
		tgt := scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path, Protocol: "tcp", Port: portOfURL(parsed)}
		if d := e.snapshot.EvaluateAction(tgt, "httpget", e.now()); !d.Allowed {
			res.Blocked++
			return
		}
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
				res.Blocked++
				return
			}
		}
		res.Requested++
		creq := req
		if len(req.Headers) > 0 {
			h := make(map[string]string, len(req.Headers))
			for k, v := range req.Headers {
				h[k] = substChainVars(v, vars)
			}
			creq.Headers = h
		}
		creq.Body = substChainVars(req.Body, vars)
		status, body, headers, err := e.fetchVia(ctx, client, creq, full)
		if err != nil {
			res.Errors = append(res.Errors, tmpl.ID+": "+err.Error())
			return
		}
		view := newResponseView(status, body, headers)
		for name, vals := range req.extract(view) {
			if len(vals) > 0 {
				vars[name] = vals[0]
			}
		}
		if len(req.Matchers) > 0 {
			hadMatchers = true
			if !req.matches(view) {
				allMatched = false
			}
		}
		lastFull, lastStatus, lastBody = full, status, body
	}
	if !hadMatchers || !allMatched {
		return
	}
	sum := sha256.Sum256(lastBody)
	res.Matches = append(res.Matches, Match{
		TemplateID:   tmpl.ID,
		Name:         tmpl.Info.Name,
		Severity:     tmpl.Info.Severity,
		CVE:          tmpl.Info.CVE,
		CWE:          tmpl.Info.CWE,
		Tags:         tmpl.Info.Tags,
		Prerequisite: tmpl.Info.Prerequisite,
		URL:          lastFull,
		Method:       tmpl.Requests[len(tmpl.Requests)-1].Method,
		Status:       lastStatus,
		ContentHash:  hex.EncodeToString(sum[:]),
	})
}

func substChainVars(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func substituteVars(s string, u *url.URL) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	base := u.Scheme + "://" + u.Host
	r := strings.NewReplacer(
		"{{BaseURL}}", base,
		"{{RootURL}}", base,
		"{{Hostname}}", u.Host,
		"{{Host}}", u.Hostname(),
		"{{Port}}", u.Port(),
	)
	return r.Replace(s)
}

func (e *Engine) reflectionConfirmed(ctx context.Context, req Request, full string) bool {
	q := strings.IndexByte(full, '?')
	if q < 0 {
		return false
	}
	control := full[:q]
	cstatus, cbody, cheaders, err := e.fetch(ctx, req, control)
	if err != nil {
		return false
	}
	if req.matches(newResponseView(cstatus, cbody, cheaders)) {
		return false
	}
	return true
}

func portOfURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func (e *Engine) fetch(ctx context.Context, req Request, full string) (int, []byte, map[string]string, error) {
	return e.fetchVia(ctx, e.client, req, full)
}

func (e *Engine) chainClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:       e.client.Timeout,
		Transport:     e.client.Transport,
		CheckRedirect: e.client.CheckRedirect,
		Jar:           jar,
	}
}

func (e *Engine) fetchVia(ctx context.Context, client *http.Client, req Request, full string) (int, []byte, map[string]string, error) {
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, full, bodyReader)
	if err != nil {
		return 0, nil, nil, err
	}
	httpReq.Header.Set("User-Agent", "nullrecon/0.1")
	httpReq.Header.Set("Accept", "*/*")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, substituteVars(v, httpReq.URL))
	}
	if req.Body != "" {
		if sub := substituteVars(req.Body, httpReq.URL); sub != req.Body {
			httpReq.Body = io.NopCloser(strings.NewReader(sub))
			httpReq.ContentLength = int64(len(sub))
		}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, e.maxBody))
	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	return resp.StatusCode, body, headers, nil
}
