package dnsaudit

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Result struct {
	Domain      string    `json:"domain"`
	Nameservers []string  `json:"nameservers,omitempty"`
	Findings    []Finding `json:"findings"`
	Blocked     bool      `json:"blocked,omitempty"`
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	resolver *net.Resolver
	timeout  time.Duration
	now      func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		resolver: net.DefaultResolver,
		timeout:  6 * time.Second,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) Scan(ctx context.Context, domain string) (Result, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	res := Result{Domain: domain, Findings: []Finding{}}

	tgt := scopeguard.Target{Host: domain, Port: 53, Protocol: "tcp"}
	if d := e.snapshot.EvaluateAction(tgt, "dnsresolve", e.now()); !d.Allowed {
		res.Blocked = true
		return res, nil
	}
	if e.budget != nil {
		if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 3}); err != nil {
			res.Blocked = true
			return res, nil
		}
	}

	if f := e.checkSPF(ctx, domain); f != nil {
		res.Findings = append(res.Findings, *f)
	}
	if f := e.checkDMARC(ctx, domain); f != nil {
		res.Findings = append(res.Findings, *f)
	}

	nss, _ := e.resolver.LookupNS(ctx, domain)
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		res.Nameservers = append(res.Nameservers, host)
		if e.axfrAllowed(ctx, net.JoinHostPort(host, "53"), domain) {
			res.Findings = append(res.Findings, Finding{
				ID:       "dns-zone-transfer",
				Severity: "high",
				Detail:   "nameserver " + host + " allows AXFR zone transfer for " + domain,
			})
		}
	}
	return res, nil
}

func (e *Engine) checkSPF(ctx context.Context, domain string) *Finding {
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil
	}
	return classifySPF(txts)
}

func classifySPF(txts []string) *Finding {
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			if strings.Contains(strings.ToLower(txt), "+all") {
				return &Finding{ID: "spf-permissive", Severity: "medium", Detail: "SPF record ends with +all, permitting any sender"}
			}
			return nil
		}
	}
	return &Finding{ID: "spf-missing", Severity: "low", Detail: "no SPF record, domain is easier to spoof in email"}
}

func (e *Engine) checkDMARC(ctx context.Context, domain string) *Finding {
	txts, err := e.resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return &Finding{ID: "dmarc-missing", Severity: "low", Detail: "no DMARC record at _dmarc." + domain}
	}
	return classifyDMARC(txts)
}

func classifyDMARC(txts []string) *Finding {
	for _, txt := range txts {
		low := strings.ToLower(txt)
		if strings.HasPrefix(low, "v=dmarc1") {
			if strings.Contains(low, "p=none") {
				return &Finding{ID: "dmarc-policy-none", Severity: "low", Detail: "DMARC policy is p=none (monitor only, not enforced)"}
			}
			return nil
		}
	}
	return &Finding{ID: "dmarc-missing", Severity: "low", Detail: "no DMARC policy record found"}
}

func (e *Engine) axfrAllowed(ctx context.Context, address, domain string) bool {
	dialer := &net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(e.now().Add(e.timeout))

	query := buildAXFRQuery(domain)
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return false
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return false
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	if msgLen < 12 {
		return false
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return false
	}
	rcode, answers := parseDNSResponse(msg)
	return rcode == 0 && answers > 0
}

func buildAXFRQuery(domain string) []byte {
	var b []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1a2b)
	binary.BigEndian.PutUint16(header[4:6], 1)
	b = append(b, header...)
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], 252)
	binary.BigEndian.PutUint16(qtype[2:4], 1)
	b = append(b, qtype...)
	return b
}

func parseDNSResponse(msg []byte) (rcode int, answers int) {
	if len(msg) < 12 {
		return -1, 0
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode = int(flags & 0x000f)
	answers = int(binary.BigEndian.Uint16(msg[6:8]))
	return rcode, answers
}
