package template

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
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
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	client   *http.Client
	maxBody  int64
	now      func() time.Time
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
		httpReq.Header.Set(k, v)
	}
	resp, err := e.client.Do(httpReq)
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
