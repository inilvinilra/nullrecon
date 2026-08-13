package exposure

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/secretscan"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

type SecretHit struct {
	DetectorID  string `json:"detectorId"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Fingerprint string `json:"fingerprint"`
	Preview     string `json:"preview"`
}

type Finding struct {
	SignatureID     string      `json:"signatureId"`
	Category        string      `json:"category"`
	Severity        string      `json:"severity"`
	URL             string      `json:"url"`
	Status          int         `json:"status"`
	State           string      `json:"state"`
	Reasons         []string    `json:"reasons"`
	EvidencePreview string      `json:"evidencePreview,omitempty"`
	ContentHash     string      `json:"contentHash"`
	BodyBytes       int         `json:"bodyBytes"`
	Secrets         []SecretHit `json:"secrets,omitempty"`
}

type Result struct {
	Target    string    `json:"target"`
	Findings  []Finding `json:"findings"`
	Requested int       `json:"requested"`
	Blocked   int       `json:"blocked"`
	Errors    []string  `json:"errors,omitempty"`
}

type Engine struct {
	snapshot  scopeguard.Snapshot
	budget    *budgetguard.Guard
	redactor  *redaction.Redactor
	set       *SignatureSet
	detectors *secretscan.DetectorSet
	client    *http.Client
	maxBody   int64
	timeout   time.Duration
	now       func() time.Time
}

func (e *Engine) WithSecretDetectors(set *secretscan.DetectorSet) *Engine {
	e.detectors = set
	return e
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard, redactor *redaction.Redactor, set *SignatureSet) *Engine {
	timeout := 10 * time.Second
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		redactor: redactor,
		set:      set,
		maxBody:  256 << 10,
		timeout:  timeout,
		now:      func() time.Time { return time.Now().UTC() },
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (e *Engine) Scan(ctx context.Context, target string) (Result, error) {
	base, err := url.Parse(strings.TrimRight(target, "/"))
	if err != nil || base.Host == "" {
		return Result{}, fmt.Errorf("exposure: invalid target %q", target)
	}
	res := Result{Target: base.String()}
	for _, sig := range e.set.signatures {
		full := base.String() + "/" + strings.TrimLeft(sig.Path, "/")
		parsed, perr := url.Parse(full)
		if perr != nil {
			continue
		}
		if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path}, "httpget", e.now()); !d.Allowed {
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
		status, body, err := e.fetch(ctx, full)
		if err != nil {
			res.Errors = append(res.Errors, sig.ID+": "+err.Error())
			continue
		}
		if status < 200 || status >= 300 {
			continue
		}
		reasons, ok := sig.matches(body)
		if !ok {
			continue
		}
		res.Findings = append(res.Findings, e.buildFinding(sig, full, status, body, reasons))
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity != res.Findings[j].Severity {
			return severityRank(res.Findings[i].Severity) < severityRank(res.Findings[j].Severity)
		}
		return res.Findings[i].SignatureID < res.Findings[j].SignatureID
	})
	return res, nil
}

func (e *Engine) buildFinding(sig compiledSignature, full string, status int, body []byte, reasons []string) Finding {
	sum := sha256.Sum256(body)
	finding := Finding{
		SignatureID: sig.ID,
		Category:    sig.Category,
		Severity:    sig.Severity,
		URL:         full,
		Status:      status,
		State:       "confirmed",
		Reasons:     reasons,
		ContentHash: hex.EncodeToString(sum[:]),
		BodyBytes:   len(body),
	}
	if sig.Category != "leak" {
		finding.EvidencePreview = e.preview(body)
	}
	if e.detectors != nil {
		scan := secretscan.Scan(e.detectors, body, full)
		for _, cand := range scan.Candidates {
			finding.Secrets = append(finding.Secrets, SecretHit{
				DetectorID:  cand.DetectorID,
				Category:    cand.Category,
				Severity:    cand.Severity,
				Fingerprint: cand.Fingerprint,
				Preview:     cand.Preview,
			})
			if severityRank(cand.Severity) < severityRank(finding.Severity) {
				finding.Severity = cand.Severity
			}
		}
	}
	return finding
}

func (e *Engine) preview(body []byte) string {
	snippet := body
	if len(snippet) > 256 {
		snippet = snippet[:256]
	}
	text := strings.ToValidUTF8(string(snippet), "")
	if e.redactor != nil {
		return e.redactor.Redact(text).Text
	}
	return text
}

func (e *Engine) fetch(ctx context.Context, full string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "nullrecon/0.1")
	req.Header.Set("Accept", "*/*")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, e.maxBody))
	return resp.StatusCode, body, nil
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}
