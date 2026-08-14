package tlsscan

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dnsNames,omitempty"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	SelfSigned bool      `json:"selfSigned"`
	SigAlg     string    `json:"signatureAlgorithm"`
	KeyBits    int       `json:"keyBits,omitempty"`
}

type Result struct {
	Target     string          `json:"target"`
	Host       string          `json:"host"`
	Negotiated string          `json:"negotiated,omitempty"`
	Protocols  map[string]bool `json:"protocols"`
	Cert       *CertInfo       `json:"cert,omitempty"`
	Findings   []Finding       `json:"findings"`
	Blocked    bool            `json:"blocked,omitempty"`
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	timeout  time.Duration
	now      func() time.Time
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard) *Engine {
	return &Engine{
		snapshot: snapshot,
		budget:   budget,
		timeout:  8 * time.Second,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

var versions = []struct {
	name string
	id   uint16
}{
	{"tls1.0", tls.VersionTLS10},
	{"tls1.1", tls.VersionTLS11},
	{"tls1.2", tls.VersionTLS12},
	{"tls1.3", tls.VersionTLS13},
}

func (e *Engine) Scan(ctx context.Context, hostport string) (Result, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		portStr = "443"
		hostport = net.JoinHostPort(host, portStr)
	}
	port, _ := strconv.Atoi(portStr)
	res := Result{Target: hostport, Host: host, Protocols: map[string]bool{}, Findings: []Finding{}}

	tgt := scopeguard.Target{Host: host, Port: port, Protocol: "tcp"}
	if d := e.snapshot.EvaluateAction(tgt, "tcpconnect", e.now()); !d.Allowed {
		res.Blocked = true
		return res, nil
	}
	if e.budget != nil {
		if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: int64(len(versions))}); err != nil {
			res.Blocked = true
			return res, nil
		}
	}

	var leaf *x509.Certificate
	for _, v := range versions {
		state, ok := e.handshake(ctx, hostport, host, v.id)
		if !ok {
			continue
		}
		res.Protocols[v.name] = true
		if leaf == nil && len(state.PeerCertificates) > 0 {
			leaf = state.PeerCertificates[0]
			res.Negotiated = v.name
		}
	}

	if leaf == nil {
		return res, fmt.Errorf("tlsscan: no TLS handshake succeeded for %s", hostport)
	}
	res.Cert = certInfo(leaf)
	res.Findings = e.evaluate(res, leaf, host)
	return res, nil
}

func (e *Engine) handshake(ctx context.Context, hostport, sni string, version uint16) (tls.ConnectionState, bool) {
	dialer := &net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return tls.ConnectionState{}, false
	}
	defer conn.Close()
	conn.SetDeadline(e.now().Add(e.timeout))
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, false
	}
	return tconn.ConnectionState(), true
}

func certInfo(c *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		DNSNames:   c.DNSNames,
		NotBefore:  c.NotBefore.UTC(),
		NotAfter:   c.NotAfter.UTC(),
		SelfSigned: c.Subject.String() == c.Issuer.String(),
		SigAlg:     c.SignatureAlgorithm.String(),
	}
	if pub, ok := c.PublicKey.(*rsa.PublicKey); ok {
		info.KeyBits = pub.N.BitLen()
	}
	return info
}

func (e *Engine) evaluate(res Result, leaf *x509.Certificate, host string) []Finding {
	var findings []Finding
	add := func(id, sev, detail string) {
		findings = append(findings, Finding{ID: id, Severity: sev, Detail: detail})
	}
	now := e.now()

	if res.Protocols["tls1.0"] {
		add("tls-version-1.0", "medium", "TLS 1.0 is deprecated and enabled")
	}
	if res.Protocols["tls1.1"] {
		add("tls-version-1.1", "medium", "TLS 1.1 is deprecated and enabled")
	}

	if now.After(leaf.NotAfter) {
		add("certificate-expired", "high", "certificate expired on "+leaf.NotAfter.Format("2006-01-02"))
	} else if leaf.NotAfter.Sub(now) < 21*24*time.Hour {
		add("certificate-expiring", "medium", "certificate expires on "+leaf.NotAfter.Format("2006-01-02"))
	}
	if now.Before(leaf.NotBefore) {
		add("certificate-not-yet-valid", "medium", "certificate not valid before "+leaf.NotBefore.Format("2006-01-02"))
	}
	if leaf.Subject.String() == leaf.Issuer.String() {
		add("self-signed-certificate", "medium", "certificate is self-signed")
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		add("weak-signature-algorithm", "medium", "certificate signed with weak algorithm "+leaf.SignatureAlgorithm.String())
	}
	if info := res.Cert; info != nil && info.KeyBits > 0 && info.KeyBits < 2048 {
		add("weak-rsa-key", "medium", "RSA key size "+strconv.Itoa(info.KeyBits)+" is below 2048 bits")
	}
	if host != "" && net.ParseIP(host) == nil {
		if err := leaf.VerifyHostname(host); err != nil {
			add("hostname-mismatch", "medium", "certificate is not valid for "+host)
		}
	}
	return findings
}
