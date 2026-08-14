package sqli

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Finding struct {
	Parameter string `json:"parameter"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Confirmed bool   `json:"confirmed"`
	Evidence  string `json:"evidence"`
}

type Result struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
	Tested   int       `json:"tested"`
	Blocked  bool      `json:"blocked,omitempty"`
}

type timerFunc func(ctx context.Context, u *url.URL, param, injected string) float64

type Engine struct {
	snapshot    scopeguard.Snapshot
	budget      *budgetguard.Guard
	client      *http.Client
	now         func() time.Time
	timeConfirm timerFunc
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	timeout := 20 * time.Second
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) WithTimeConfirm() *Engine {
	e.timeConfirm = func(ctx context.Context, u *url.URL, param, injected string) float64 {
		start := time.Now()
		if _, ok := e.fetchWith(ctx, u, param, injected); !ok {
			return -1
		}
		return time.Since(start).Seconds()
	}
	return e
}

var sqlErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"microsoft ole db provider for sql server",
	"microsoft ole db provider for odbc drivers",
	"odbc microsoft access driver",
	"microsoft jet database",
	"incorrect syntax near",
	"pg_query()",
	"postgresql query failed",
	"sqlite3::query",
	"sqlstate[",
	"ora-01756",
	"ora-00933",
	"conversion failed when converting",
}

type payloadPair struct {
	name        string
	trueSuffix  string
	falseSuffix string
}

var booleanPairs = []payloadPair{
	{"numeric", " AND 1=1", " AND 1=2"},
	{"single-quote", "' AND '1'='1", "' AND '1'='2"},
	{"double-quote", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
}

func (e *Engine) Scan(ctx context.Context, target string) (Result, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return Result{}, err
	}
	res := Result{Target: u.String(), Findings: []Finding{}}
	tgt := scopeguard.Target{Host: u.Hostname(), Path: u.Path, Protocol: "tcp", Port: portOf(u)}
	if d := e.snapshot.EvaluateAction(tgt, "httpget", e.now()); !d.Allowed {
		res.Blocked = true
		return res, nil
	}
	params := u.Query()
	if len(params) == 0 {
		return res, nil
	}
	base, ok := e.fetch(ctx, u.String())
	if !ok {
		return res, nil
	}
	for param, values := range params {
		if len(values) == 0 {
			continue
		}
		res.Tested++
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 7}); err != nil {
				res.Blocked = true
				return res, nil
			}
		}
		if f := e.testParam(ctx, u, param, values[0], base); f != nil {
			res.Findings = append(res.Findings, *f)
		}
	}
	return res, nil
}

func (e *Engine) testParam(ctx context.Context, u *url.URL, param, value string, base response) *Finding {
	errResp, ok := e.fetchWith(ctx, u, param, value+"'")
	if ok && !hasSQLError(base.body) && hasSQLError(errResp.body) {
		return &Finding{Parameter: param, Type: "error-based", Severity: "critical", Confirmed: true,
			Evidence: "injecting a single quote surfaced a database error not present in the baseline"}
	}
	for _, pair := range booleanPairs {
		tResp, okT := e.fetchWith(ctx, u, param, value+pair.trueSuffix)
		fResp, okF := e.fetchWith(ctx, u, param, value+pair.falseSuffix)
		if !okT || !okF {
			continue
		}
		if similar(base, tResp) && !similar(base, fResp) {
			ev := "TRUE payload matched the baseline while FALSE payload diverged (status " +
				itoa(base.status) + "/" + itoa(tResp.status) + "/" + itoa(fResp.status) + ")"
			if e.timeConfirm != nil {
				if delayed := e.confirmTimeBased(ctx, u, param, value); delayed != "" {
					ev += "; " + delayed
				}
			}
			return &Finding{Parameter: param, Type: "boolean-based (" + pair.name + ")", Severity: "critical", Confirmed: true, Evidence: ev}
		}
	}
	if e.timeConfirm != nil {
		if delayed := e.confirmTimeBased(ctx, u, param, value); delayed != "" {
			return &Finding{Parameter: param, Type: "time-based blind", Severity: "critical", Confirmed: true, Evidence: delayed}
		}
	}
	return nil
}

var timePayloads = []struct {
	name   string
	inject func(value string, delay int) string
}{
	{"mssql", func(v string, d int) string { return v + ";WAITFOR DELAY '0:0:" + itoa(d) + "'--" }},
	{"mysql", func(v string, d int) string { return v + " AND SLEEP(" + itoa(d) + ")-- -" }},
	{"postgres", func(v string, d int) string { return v + ";SELECT pg_sleep(" + itoa(d) + ")--" }},
}

func (e *Engine) confirmTimeBased(ctx context.Context, u *url.URL, param, value string) string {
	const delay = 5
	for _, p := range timePayloads {
		control := e.timeConfirm(ctx, u, param, p.inject(value, 0))
		if control < 0 {
			continue
		}
		slow := e.timeConfirm(ctx, u, param, p.inject(value, delay))
		if slow < 0 {
			continue
		}
		if slow >= control+float64(delay)-1 && slow >= 4 {
			return "time-based confirmed via " + p.name + " (" + fmtDur(control) + " control vs " + fmtDur(slow) + " with a " + itoa(delay) + "s delay injected)"
		}
	}
	return ""
}

func fmtDur(seconds float64) string {
	whole := int(seconds)
	tenths := int((seconds - float64(whole)) * 10)
	return itoa(whole) + "." + itoa(tenths) + "s"
}

type response struct {
	status int
	body   string
}

func (e *Engine) fetch(ctx context.Context, full string) (response, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return response{}, false
	}
	req.Header.Set("User-Agent", "nullrecon/0.1")
	resp, err := e.client.Do(req)
	if err != nil {
		return response{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return response{status: resp.StatusCode, body: string(body)}, true
}

func (e *Engine) fetchWith(ctx context.Context, base *url.URL, param, value string) (response, bool) {
	u := *base
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return e.fetch(ctx, u.String())
}

func hasSQLError(body string) bool {
	low := strings.ToLower(body)
	for _, sig := range sqlErrors {
		if strings.Contains(low, sig) {
			return true
		}
	}
	return false
}

func similar(a, b response) bool {
	if a.status != b.status {
		return false
	}
	la, lb := len(a.body), len(b.body)
	if la == 0 && lb == 0 {
		return true
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	larger := la
	if lb > larger {
		larger = lb
	}
	return float64(diff)/float64(larger) < 0.05
}

func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n := atoi(p); n > 0 {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
