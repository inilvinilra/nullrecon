package originip

import (
	"context"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

type OriginLeak struct {
	IP       string `json:"ip"`
	Source   string `json:"source"`
	Detail   string `json:"detail,omitempty"`
	InCDN    bool   `json:"inCdn"`
	Provider string `json:"provider,omitempty"`
	PTR      string `json:"ptr,omitempty"`
}

var ip4Pattern = regexp.MustCompile(`ip4:([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/[0-9]{1,2})?`)
var ip6Pattern = regexp.MustCompile(`ip6:([0-9a-fA-F:]+)(?:/[0-9]{1,3})?`)
var bareIP4 = regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)

type txtIP struct {
	ip     string
	source string
	detail string
}

func extractTXTIPs(txt string) []txtIP {
	var out []txtIP
	for _, m := range ip4Pattern.FindAllStringSubmatch(txt, -1) {
		out = append(out, txtIP{m[1], "spf", "SPF ip4"})
	}
	for _, m := range ip6Pattern.FindAllStringSubmatch(txt, -1) {
		out = append(out, txtIP{m[1], "spf", "SPF ip6"})
	}
	if !strings.Contains(strings.ToLower(txt), "spf") {
		for _, m := range bareIP4.FindAllStringSubmatch(txt, -1) {
			out = append(out, txtIP{m[1], "txt", "TXT record"})
		}
	}
	return out
}

func leakResolver() *net.Resolver {
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	var idx int
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			idx++
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp", servers[idx%len(servers)])
		},
	}
}

func (e *Engine) DNSLeaks(ctx context.Context, domain string) []OriginLeak {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	r := leakResolver()
	found := map[string]*OriginLeak{}
	record := func(ip, source, detail string) {
		ip = strings.TrimSpace(ip)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() {
			return
		}
		if existing, ok := found[ip]; ok {
			if !strings.Contains(existing.Source, source) {
				existing.Source += "+" + source
			}
			return
		}
		leak := &OriginLeak{IP: ip, Source: source, Detail: detail}
		if e.nm != nil {
			if provider, in := e.nm.Classify(ip); in {
				leak.InCDN = true
				leak.Provider = provider
			}
		}
		found[ip] = leak
	}

	tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if txts, err := r.LookupTXT(tctx, domain); err == nil {
		for _, txt := range txts {
			for _, hit := range extractTXTIPs(txt) {
				record(hit.ip, hit.source, hit.detail)
			}
		}
	}

	if mxs, err := r.LookupMX(tctx, domain); err == nil {
		for _, mx := range mxs {
			host := strings.TrimSuffix(mx.Host, ".")
			if addrs, aerr := r.LookupIPAddr(tctx, host); aerr == nil {
				for _, a := range addrs {
					record(a.IP.String(), "mx", "MX "+host)
				}
			}
		}
	}

	if addrs, err := r.LookupIPAddr(tctx, domain); err == nil {
		for _, a := range addrs {
			record(a.IP.String(), "a", "A/AAAA record")
		}
	}

	for ip, leak := range found {
		if names, err := r.LookupAddr(tctx, ip); err == nil && len(names) > 0 {
			leak.PTR = strings.TrimSuffix(names[0], ".")
		}
	}

	out := make([]OriginLeak, 0, len(found))
	for _, leak := range found {
		out = append(out, *leak)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].InCDN != out[j].InCDN {
			return !out[i].InCDN
		}
		return out[i].IP < out[j].IP
	})
	return out
}
