package portscan

import (
	"context"

	"net"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func snapshotFor(t *testing.T, cidrs []string, ports []int, mode policy.Mode) scopeguard.Snapshot {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"passive", "safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	scope := scopeguard.NewScope()
	scope.CIDRs = cidrs
	scope.Ports = ports
	scope.Protocols = []string{"tcp"}
	snap, err := scopeguard.Compile(project, authz, scope, mode, now)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func openListener(t *testing.T) (int, net.Listener) {
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
			conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ln
}

func TestScanOpenPort(t *testing.T) {
	port, _ := openListener(t)
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil).WithBanners(true)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ports) != 1 || !res.Ports[0].Open {
		t.Fatalf("port must be open: %+v", res)
	}
	if res.Ports[0].Banner == "" {
		t.Fatal("banner must be captured")
	}
}

func TestScanClosedPort(t *testing.T) {
	port, ln := openListener(t)
	ln.Close()
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ports) != 1 || res.Ports[0].Open {
		t.Fatalf("closed port must report closed: %+v", res)
	}
}

func TestOutOfScopePortBlocked(t *testing.T) {
	port, _ := openListener(t)
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{443}, policy.ModeSafeActive)
	e := New(snap, nil)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ports) != 0 || len(res.Blocked) != 1 {
		t.Fatalf("unlisted port must be blocked pre-flight: %+v", res)
	}
}

func TestOutOfScopeIPBlocked(t *testing.T) {
	port, _ := openListener(t)
	snap := snapshotFor(t, []string{"203.0.113.0/28"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil)
	res, _ := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if len(res.Ports) != 0 {
		t.Fatal("out-of-scope ip must never be dialed")
	}
}

func TestBudgetLimitsRequests(t *testing.T) {
	port, _ := openListener(t)
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port, port + 1}, policy.ModeSafeActive)
	budget := budgetguard.New("test", budgetguard.Budget{budgetguard.DimRequests: 1}, nil)
	e := New(snap, budget)
	res, _ := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port, port + 1})
	if len(res.Ports)+len(res.Blocked) != 2 {
		t.Fatalf("all ports must be accounted for: %+v", res)
	}
	if len(res.Blocked) < 1 {
		t.Fatalf("budget must block at least one port: %+v", res)
	}
}

func TestActiveHTTPBannerAndTargetString(t *testing.T) {
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
				buf := make([]byte, 512)
				c.Read(buf)
				c.Write([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 2\r\n\r\nok"))
				c.Close()
			}(conn)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil).WithBanners(true)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "127.0.0.1" {
		t.Fatalf("target must not be doubled: %q", res.Target)
	}
	if len(res.Ports) != 1 || !res.Ports[0].Open {
		t.Fatalf("port must be open: %+v", res)
	}
	if !strings.Contains(res.Ports[0].Banner, "Apache/2.4.49") {
		t.Fatalf("active HTTP banner must capture Server header, got %q", res.Ports[0].Banner)
	}
}

func serveOnce(t *testing.T, handler func(net.Conn)) int {
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
			go handler(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestServiceProbeRedis(t *testing.T) {
	port := serveOnce(t, func(c net.Conn) {
		buf := make([]byte, 64)
		c.Read(buf)
		c.Write([]byte("+PONG\r\n"))
		c.Read(buf)
		c.Write([]byte("$23\r\n# Server\r\nredis_version:7.4.5\r\n"))
		c.Close()
	})
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil).WithBanners(true)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ports) != 1 || res.Ports[0].Banner != "Redis 7.4.5" {
		t.Fatalf("redis version banner expected, got %q", res.Ports[0].Banner)
	}
}

func TestServiceProbePostgres(t *testing.T) {
	port := serveOnce(t, func(c net.Conn) {
		buf := make([]byte, 8)
		c.Read(buf)
		c.Write([]byte("N"))
		c.Close()
	})
	snap := snapshotFor(t, []string{"127.0.0.0/8"}, []int{port}, policy.ModeSafeActive)
	e := New(snap, nil).WithBanners(true)
	res, err := e.Scan(context.Background(), scopeguard.Target{IP: "127.0.0.1"}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ports) != 1 || res.Ports[0].Banner != "PostgreSQL" {
		t.Fatalf("postgres banner expected, got %q", res.Ports[0].Banner)
	}
}
