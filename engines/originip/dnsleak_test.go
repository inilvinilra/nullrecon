package originip

import "testing"

func TestExtractTXTIPsFromSPF(t *testing.T) {
	got := extractTXTIPs("v=spf1 +mx +ip4:185.25.101.98 +ip4:81.8.91.196 ip6:2606:4700::1 -all")
	ips := map[string]string{}
	for _, h := range got {
		ips[h.ip] = h.source
	}
	if ips["185.25.101.98"] != "spf" || ips["81.8.91.196"] != "spf" {
		t.Fatalf("SPF ip4 addresses must be extracted as spf leaks: %+v", got)
	}
	if ips["2606:4700::1"] != "spf" {
		t.Fatalf("SPF ip6 must be extracted: %+v", got)
	}
}

func TestExtractTXTIPsIgnoresNonSPFVerification(t *testing.T) {
	got := extractTXTIPs("google-site-verification=abc123def456")
	if len(got) != 0 {
		t.Fatalf("verification tokens must not yield IPs: %+v", got)
	}
}

func TestExtractTXTIPsBareIPOnlyOutsideSPF(t *testing.T) {
	got := extractTXTIPs("server pool 203.0.113.5 primary")
	if len(got) != 1 || got[0].ip != "203.0.113.5" || got[0].source != "txt" {
		t.Fatalf("bare IP in a non-SPF TXT must be captured as txt: %+v", got)
	}
}
