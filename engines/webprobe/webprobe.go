package webprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/engines/fingerprint"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

type TLSInfo struct {
	Version     string   `json:"version"`
	Cipher      string   `json:"cipher"`
	SubjectCN   string   `json:"subjectCN,omitempty"`
	IssuerCN    string   `json:"issuerCN,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	NotAfter    string   `json:"notAfter,omitempty"`
	VerifyError string   `json:"verifyError,omitempty"`
}

type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

type Result struct {
	URL             string            `json:"url"`
	FinalURL        string            `json:"finalUrl"`
	Status          int               `json:"status"`
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         []string          `json:"cookies,omitempty"`
	TLS             *TLSInfo          `json:"tls,omitempty"`
	Title           string            `json:"title,omitempty"`
	ContentHash     string            `json:"contentHash,omitempty"`
	BodyBytes       int               `json:"bodyBytes"`
	BodySnippet     string            `json:"-"`
	FaviconMMH3     *int32            `json:"faviconMmh3,omitempty"`
	FaviconSHA256   string            `json:"faviconSha256,omitempty"`
	TimingMS        int64             `json:"timingMs"`
	Hops            []Hop             `json:"hops,omitempty"`
	BlockedRedirect string            `json:"blockedRedirect,omitempty"`
	Errors          []string          `json:"errors,omitempty"`
}

type Engine struct {
	snapshot     scopeguard.Snapshot
	budget       *budgetguard.Guard
	redactor     *redaction.Redactor
	maxBody      int64
	maxRedirects int
	timeout      time.Duration
	now          func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard, redactor *redaction.Redactor) *Engine {
	return &Engine{
		snapshot:     snapshot,
		budget:       budget,
		redactor:     redactor,
		maxBody:      64 << 10,
		maxRedirects: 8,
		timeout:      10 * time.Second,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

var errRedirectBlocked = fmt.Errorf("webprobe: redirect blocked by scope")

func (e *Engine) Probe(ctx context.Context, rawURL string) (Result, error) {
	res := Result{URL: rawURL}
	start := e.now()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return res, err
	}
	host := parsed.Hostname()
	if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: host, Path: parsed.Path}, "httpget", e.now()); !d.Allowed {
		res.Errors = append(res.Errors, strings.Join(d.Reasons, "; "))
		return res, fmt.Errorf("webprobe: %s", d.Reasons[0])
	}
	if e.budget != nil {
		if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
			return res, err
		}
	}
	redirects := 0
	client := &http.Client{
		Timeout: e.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects++
			if redirects > e.maxRedirects {
				return fmt.Errorf("webprobe: redirect budget exceeded")
			}
			if e.budget != nil {
				if err := e.budget.Report(budgetguard.DimRedirects, 1); err != nil {
					return err
				}
			}
			location := req.URL
			pivot := e.snapshot.EvaluatePivot(
				scopeguard.Target{Host: via[len(via)-1].URL.Hostname()},
				scopeguard.Target{Host: location.Hostname(), Path: location.Path},
				e.now())
			if !pivot.Allowed {
				res.BlockedRedirect = location.String()
				return errRedirectBlocked
			}
			res.Hops = append(res.Hops, Hop{URL: via[len(via)-1].URL.String(), Status: 0, Location: location.String()})
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "nullrecon/0.1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), errRedirectBlocked.Error()) {
			res.TimingMS = e.now().Sub(start).Milliseconds()
			return res, nil
		}
		return res, err
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	res.FinalURL = resp.Request.URL.String()
	res.Headers = map[string]string{}
	for k, v := range resp.Header {
		res.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	if e.redactor != nil {
		res.Headers = e.redactor.RedactMap(res.Headers)
	}
	for _, c := range resp.Cookies() {
		res.Cookies = append(res.Cookies, c.Name)
	}
	if resp.TLS != nil {
		res.TLS = describeTLS(resp.TLS, parsed.Hostname())
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, e.maxBody))
	if err != nil {
		res.Errors = append(res.Errors, "body: "+err.Error())
	}
	res.BodyBytes = len(body)
	sum := sha256.Sum256(body)
	res.ContentHash = hex.EncodeToString(sum[:])
	res.Title = extractTitle(string(body))
	if e.redactor != nil {
		res.Title = e.redactor.Redact(res.Title).Text
	}
	snippet := body
	if len(snippet) > 4096 {
		snippet = snippet[:4096]
	}
	res.BodySnippet = string(snippet)
	res.TimingMS = e.now().Sub(start).Milliseconds()
	e.probeFavicon(ctx, client, parsed, &res)
	return res, nil
}

func (e *Engine) probeFavicon(ctx context.Context, client *http.Client, parsed *url.URL, res *Result) {
	favURL := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/favicon.ico"}).String()
	if e.budget != nil {
		if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
			return
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, favURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(data) == 0 {
		return
	}
	mmh := fingerprint.FaviconMMH3(data)
	res.FaviconMMH3 = &mmh
	sum := sha256.Sum256(data)
	res.FaviconSHA256 = hex.EncodeToString(sum[:])
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>([^<]{0,256})</title>`)

func extractTitle(body string) string {
	m := titlePattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func describeTLS(state *tls.ConnectionState, host string) *TLSInfo {
	info := &TLSInfo{Version: tlsVersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite)}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.SubjectCN = cert.Subject.CommonName
		info.IssuerCN = cert.Issuer.CommonName
		info.SANs = cert.DNSNames
		info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool()}
		for _, intermediate := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(intermediate)
		}
		if _, err := cert.Verify(opts); err != nil {
			info.VerifyError = err.Error()
		}
	}
	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}
