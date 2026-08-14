package portscan

import (
	"context"
	"net"
	"testing"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

func silentListener(t *testing.T) int {
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
			conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestScanMultiplePortsBannerSilentClosed(t *testing.T) {
	bannerPort, _ := openListener(t)
	silent := silentListener(t)
	closed := closedPort(t)

	ports := []int{bannerPort, silent, closed}
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, ports, policy.ModeSafeActive)
	e := New(snap, nil).WithBanners(true)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, ports)
	if err != nil {
		t.Fatal(err)
	}
	byPort := map[int]PortResult{}
	for _, p := range res.Ports {
		byPort[p.Port] = p
	}
	if b := byPort[bannerPort]; !b.Open || b.Banner == "" {
		t.Fatalf("banner port must be open with a banner: %+v", b)
	}
	if s := byPort[silent]; !s.Open {
		t.Fatalf("a silent service must still be reported open (not dropped for lacking a banner): %+v", s)
	}
	if s := byPort[silent]; s.Banner != "" {
		t.Fatalf("a silent service must have an empty banner, got %q", s.Banner)
	}
	if c := byPort[closed]; c.Open {
		t.Fatalf("closed port must not be reported open: %+v", c)
	}
}
