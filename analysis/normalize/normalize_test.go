package normalize

import (
	"testing"

	"github.com/nullrecon/nullrecon/domain/asset"
)

func TestHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":       "example.com",
		"*.Api.Example.com":  "api.example.com",
		"  sub.example.com ": "sub.example.com",
	}
	for in, want := range cases {
		got, err := Host(in)
		if err != nil {
			t.Fatalf("Host(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostRejects(t *testing.T) {
	for _, bad := range []string{"", "not a host", "-bad.com", "bad..com", "example.c"} {
		if _, err := Host(bad); err == nil {
			t.Fatalf("Host(%q) must fail", bad)
		}
	}
}

func TestIPCanonical(t *testing.T) {
	got, err := IP("2001:0db8:0000:0000:0000:0000:0000:0001")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2001:db8::1" {
		t.Fatalf("ipv6 must be canonical, got %q", got)
	}
	if _, err := IP("999.1.1.1"); err == nil {
		t.Fatal("invalid ip must fail")
	}
}

func TestURL(t *testing.T) {
	cases := map[string]string{
		"HTTP://Example.COM:80/path#frag":    "http://example.com/path",
		"https://example.com:443":            "https://example.com/",
		"https://example.com:8443/x?b=2&a=1": "https://example.com:8443/x?a=1&b=2",
	}
	for in, want := range cases {
		got, err := URL(in)
		if err != nil {
			t.Fatalf("URL(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("URL(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := URL("ftp://example.com"); err == nil {
		t.Fatal("non-http scheme must fail")
	}
}

func TestKindForValue(t *testing.T) {
	cases := map[string]asset.Kind{
		"192.0.2.1":            asset.KindIP,
		"203.0.113.0/24":       asset.KindCIDR,
		"example.com":          asset.KindDomain,
		"api.example.com":      asset.KindHostname,
		"https://example.com/": asset.KindURLRoot,
	}
	for in, want := range cases {
		got, err := KindForValue(in)
		if err != nil {
			t.Fatalf("KindForValue(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("KindForValue(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParentDomain(t *testing.T) {
	if got := ParentDomain("a.b.example.com"); got != "example.com" {
		t.Fatalf("got %q", got)
	}
	if got := ParentDomain("example.com"); got != "example.com" {
		t.Fatalf("got %q", got)
	}
}
