package svcaudit

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Service   string `json:"service"`
	Confirmed bool   `json:"confirmed"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

type Result struct {
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Findings []Finding `json:"findings"`
	Blocked  bool      `json:"blocked,omitempty"`
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	timeout  time.Duration
	client   *http.Client
	now      func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	timeout := 6 * time.Second
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		timeout:  timeout,
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) Scan(ctx context.Context, host string, port int) (Result, error) {
	res := Result{Host: host, Port: port, Findings: []Finding{}}
	tgt := scopeguard.Target{Host: host, Port: port, Protocol: "tcp"}
	if d := e.snapshot.EvaluateAction(tgt, "tcpconnect", e.now()); !d.Allowed {
		res.Blocked = true
		return res, nil
	}
	if e.budget != nil {
		if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 2}); err != nil {
			res.Blocked = true
			return res, nil
		}
	}
	for _, check := range e.checksFor(port) {
		if f := check(ctx, host, port); f != nil {
			res.Findings = append(res.Findings, *f)
		}
	}
	return res, nil
}

type check func(ctx context.Context, host string, port int) *Finding

func (e *Engine) checksFor(port int) []check {
	switch port {
	case 6379:
		return []check{e.checkRedis}
	case 9200, 9201:
		return []check{e.checkElasticsearch}
	case 5984, 6984:
		return []check{e.checkCouchDB}
	case 27017, 27018:
		return []check{e.checkMongoDB}
	default:
		return []check{e.checkRedis, e.checkElasticsearch, e.checkCouchDB, e.checkMongoDB}
	}
}

func (e *Engine) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: e.timeout}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, itoa(port)))
}

func (e *Engine) checkRedis(ctx context.Context, host string, port int) *Finding {
	conn, err := e.dial(ctx, host, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(e.now().Add(e.timeout))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return nil
	}
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	reply := string(buf[:n])
	if strings.Contains(reply, "NOAUTH") || strings.Contains(reply, "requires authentication") {
		return nil
	}
	if !strings.HasPrefix(reply, "+PONG") {
		return nil
	}
	conn.SetDeadline(e.now().Add(e.timeout))
	conn.Write([]byte("INFO server\r\n"))
	info := make([]byte, 2048)
	m, _ := conn.Read(info)
	version := ""
	if match := redisVersionRe.FindStringSubmatch(string(info[:m])); len(match) == 2 {
		version = match[1]
	}
	if version == "" {
		return nil
	}
	return &Finding{
		ID: "redis-unauthenticated-access", Severity: "critical", Service: "redis",
		Confirmed: true,
		Detail:    "Redis responds to unauthenticated commands; full data access without credentials",
		Evidence:  "redis_version:" + version,
	}
}

func (e *Engine) checkElasticsearch(ctx context.Context, host string, port int) *Finding {
	body, status, ok := e.httpGet(ctx, host, port, "/")
	if !ok || status != 200 {
		return nil
	}
	low := strings.ToLower(body)
	if !strings.Contains(low, "\"cluster_name\"") && !strings.Contains(low, "you know, for search") {
		return nil
	}
	idx, istatus, _ := e.httpGet(ctx, host, port, "/_cat/indices?format=json")
	confirmed := istatus == 200 && !strings.Contains(strings.ToLower(idx), "security_exception")
	ev := extractField(body, "\"number\"")
	return &Finding{
		ID: "elasticsearch-unauthenticated-access", Severity: "critical", Service: "elasticsearch",
		Confirmed: confirmed,
		Detail:    "Elasticsearch cluster is reachable without authentication",
		Evidence:  "version " + ev,
	}
}

func (e *Engine) checkCouchDB(ctx context.Context, host string, port int) *Finding {
	body, status, ok := e.httpGet(ctx, host, port, "/")
	if !ok || status != 200 || !strings.Contains(strings.ToLower(body), "\"couchdb\"") {
		return nil
	}
	dbs, dstatus, _ := e.httpGet(ctx, host, port, "/_all_dbs")
	confirmed := dstatus == 200 && strings.HasPrefix(strings.TrimSpace(dbs), "[")
	return &Finding{
		ID: "couchdb-unauthenticated-access", Severity: "critical", Service: "couchdb",
		Confirmed: confirmed,
		Detail:    "CouchDB is reachable without authentication",
		Evidence:  "version " + extractField(body, "\"version\""),
	}
}

func (e *Engine) checkMongoDB(ctx context.Context, host string, port int) *Finding {
	conn, err := e.dial(ctx, host, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(e.now().Add(e.timeout))
	if _, err := conn.Write(mongoListDatabasesQuery()); err != nil {
		return nil
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil
	}
	total := int(binary.LittleEndian.Uint32(lenBuf))
	if total < 16 || total > 1<<20 {
		return nil
	}
	rest := make([]byte, total-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil
	}
	reply := string(rest)
	if strings.Contains(reply, "requires authentication") || strings.Contains(reply, "Unauthorized") || strings.Contains(reply, "not authorized") {
		return nil
	}
	if !strings.Contains(reply, "databases") && !strings.Contains(reply, "ismaster") && !strings.Contains(reply, "isWritablePrimary") {
		return nil
	}
	return &Finding{
		ID: "mongodb-unauthenticated-access", Severity: "critical", Service: "mongodb",
		Confirmed: strings.Contains(reply, "databases"),
		Detail:    "MongoDB answers admin commands without authentication",
		Evidence:  "listDatabases accepted without credentials",
	}
}

func (e *Engine) httpGet(ctx context.Context, host string, port int, path string) (string, int, bool) {
	for _, scheme := range []string{"http", "https"} {
		url := scheme + "://" + net.JoinHostPort(host, itoa(port)) + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "nullrecon/0.1")
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return string(body), resp.StatusCode, true
	}
	return "", 0, false
}
