package dnsaudit

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func testSnapshot(t *testing.T) scopeguard.Snapshot {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.CIDRs = []string{"127.0.0.0/8"}
	scope.ExactDomains = []string{"zone.example"}
	scope.Protocols = []string{"tcp"}
	scope.PortRanges = []scopeguard.PortRange{{Start: 1, End: 65535}}
	scope.ScanClasses = []string{"dnsaudit"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestBuildAXFRQueryEncoding(t *testing.T) {
	q := buildAXFRQuery("a.bc")
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Fatal("qdcount must be 1")
	}
	want := []byte{1, 'a', 2, 'b', 'c', 0}
	got := q[12 : 12+len(want)]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("qname encoding mismatch at %d: %v vs %v", i, got, want)
		}
	}
	qtype := binary.BigEndian.Uint16(q[12+len(want) : 12+len(want)+2])
	if qtype != 252 {
		t.Fatalf("qtype must be AXFR (252), got %d", qtype)
	}
}

func TestParseDNSResponse(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8000)
	binary.BigEndian.PutUint16(msg[6:8], 5)
	rcode, answers := parseDNSResponse(msg)
	if rcode != 0 || answers != 5 {
		t.Fatalf("rcode=%d answers=%d, want 0/5", rcode, answers)
	}
	binary.BigEndian.PutUint16(msg[2:4], 0x8005)
	rcode, _ = parseDNSResponse(msg)
	if rcode != 5 {
		t.Fatalf("REFUSED rcode expected 5, got %d", rcode)
	}
}

func TestClassifySPFAndDMARC(t *testing.T) {
	if classifySPF([]string{"some other record"}).ID != "spf-missing" {
		t.Fatal("missing spf must be flagged")
	}
	if classifySPF([]string{"v=spf1 include:_spf.google.com ~all"}) != nil {
		t.Fatal("valid spf must not be flagged")
	}
	if classifySPF([]string{"v=spf1 +all"}).ID != "spf-permissive" {
		t.Fatal("+all spf must be flagged permissive")
	}
	if classifyDMARC([]string{"v=DMARC1; p=reject"}) != nil {
		t.Fatal("enforced dmarc must not be flagged")
	}
	if classifyDMARC([]string{"v=DMARC1; p=none"}).ID != "dmarc-policy-none" {
		t.Fatal("p=none dmarc must be flagged")
	}
}

func mockDNS(t *testing.T, response []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(lenBuf)))
				framed := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
				copy(framed[2:], response)
				c.Write(framed)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestAXFRAllowedAndRefused(t *testing.T) {
	allowResp := make([]byte, 12)
	binary.BigEndian.PutUint16(allowResp[2:4], 0x8000)
	binary.BigEndian.PutUint16(allowResp[6:8], 3)
	refuseResp := make([]byte, 12)
	binary.BigEndian.PutUint16(refuseResp[2:4], 0x8005)

	e := New(testSnapshot(t), nil)
	if !e.axfrAllowed(context.Background(), mockDNS(t, allowResp), "zone.example") {
		t.Fatal("AXFR with answers and RCODE 0 must be reported allowed")
	}
	if e.axfrAllowed(context.Background(), mockDNS(t, refuseResp), "zone.example") {
		t.Fatal("AXFR REFUSED must not be reported allowed")
	}
}
