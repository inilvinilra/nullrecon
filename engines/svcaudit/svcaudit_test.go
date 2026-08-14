package svcaudit

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	project := identity.NewProject("Acme", "acme")
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"authorizedtest"}, now.Add(-time.Hour), now.Add(time.Hour))
	scope := scopeguard.NewScope()
	scope.CIDRs = []string{"127.0.0.0/8"}
	scope.Protocols = []string{"tcp"}
	scope.PortRanges = []scopeguard.PortRange{{Start: 1, End: 65535}}
	scope.ScanClasses = []string{"svcaudit"}
	snap, err := scopeguard.Compile(project, authz, scope, policy.ModeAuthorizedTest, now)
	if err != nil {
		t.Fatal(err)
	}
	return New(snap, nil)
}

func tcpServer(t *testing.T, handler func(net.Conn)) (string, int) {
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
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestRedisUnauthConfirmedAndAuthNegative(t *testing.T) {
	e := testEngine(t)
	host, port := tcpServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 64)
		c.Read(buf)
		c.Write([]byte("+PONG\r\n"))
		c.Read(buf)
		c.Write([]byte("$30\r\n# Server\r\nredis_version:7.2.4\r\n"))
	})
	f := e.checkRedis(context.Background(), host, port)
	if f == nil || !f.Confirmed || f.Severity != "critical" {
		t.Fatalf("unauth redis must be confirmed critical, got %+v", f)
	}

	host2, port2 := tcpServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 64)
		c.Read(buf)
		c.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})
	if f := e.checkRedis(context.Background(), host2, port2); f != nil {
		t.Fatalf("auth-protected redis must not be flagged, got %+v", f)
	}
}

func TestElasticsearchUnauthConfirmed(t *testing.T) {
	e := testEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_cat/indices" {
			w.Write([]byte(`[{"index":".security"},{"index":"logs"}]`))
			return
		}
		w.Write([]byte(`{"name":"node1","cluster_name":"prod","version":{"number":"8.11.1"},"tagline":"You Know, for Search"}`))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv)
	f := e.checkElasticsearch(context.Background(), host, port)
	if f == nil || !f.Confirmed || f.Service != "elasticsearch" {
		t.Fatalf("open elasticsearch must be confirmed, got %+v", f)
	}
	if f.Evidence == "" {
		t.Fatal("evidence (version) must be captured")
	}
}

func TestElasticsearchSecuredNegative(t *testing.T) {
	e := testEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"type":"security_exception"}}`))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv)
	if f := e.checkElasticsearch(context.Background(), host, port); f != nil {
		t.Fatalf("secured elasticsearch must not be flagged, got %+v", f)
	}
}

func TestCouchDBUnauthConfirmed(t *testing.T) {
	e := testEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_all_dbs" {
			w.Write([]byte(`["_users","_replicator","appdata"]`))
			return
		}
		w.Write([]byte(`{"couchdb":"Welcome","version":"3.3.2"}`))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv)
	f := e.checkCouchDB(context.Background(), host, port)
	if f == nil || !f.Confirmed {
		t.Fatalf("open couchdb must be confirmed, got %+v", f)
	}
}

func TestMongoDBUnauthConfirmedAndAuthNegative(t *testing.T) {
	e := testEngine(t)
	reply := func(payload string) func(net.Conn) {
		return func(c net.Conn) {
			defer c.Close()
			hdr := make([]byte, 4)
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			total := int(binary.LittleEndian.Uint32(hdr))
			io.CopyN(io.Discard, c, int64(total-4))
			body := []byte(payload)
			out := make([]byte, 4+len(body))
			binary.LittleEndian.PutUint32(out[:4], uint32(4+len(body)))
			copy(out[4:], body)
			c.Write(out)
		}
	}
	host, port := tcpServer(t, reply("....ok....databases....admin....local...."))
	f := e.checkMongoDB(context.Background(), host, port)
	if f == nil || !f.Confirmed {
		t.Fatalf("unauth mongodb (listDatabases accepted) must be confirmed, got %+v", f)
	}

	host2, port2 := tcpServer(t, reply("....errmsg....command listDatabases requires authentication...."))
	if f := e.checkMongoDB(context.Background(), host2, port2); f != nil {
		t.Fatalf("auth-required mongodb must not be flagged, got %+v", f)
	}
}

func hostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	u := srv.URL[len("http://"):]
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}
