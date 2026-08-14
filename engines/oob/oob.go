package oob

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Interaction struct {
	Protocol   string    `json:"protocol"`
	RemoteAddr string    `json:"remoteAddr"`
	Path       string    `json:"path"`
	At         time.Time `json:"at"`
}

type Interactor struct {
	listener net.Listener
	server   *http.Server
	host     string
	mu       sync.Mutex
	hits     map[string][]Interaction
	now      func() time.Time
}

func NewInteractor(listen string) (*Interactor, error) {
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	it := &Interactor{
		listener: ln,
		host:     ln.Addr().String(),
		hits:     map[string][]Interaction{},
		now:      func() time.Time { return time.Now().UTC() },
	}
	it.server = &http.Server{Handler: http.HandlerFunc(it.handle), ReadHeaderTimeout: 5 * time.Second}
	go it.server.Serve(ln)
	return it, nil
}

func (it *Interactor) handle(w http.ResponseWriter, r *http.Request) {
	token := tokenFromPath(r.URL.Path)
	if token == "" {
		token = tokenFromHost(r.Host)
	}
	if token != "" {
		it.mu.Lock()
		it.hits[token] = append(it.hits[token], Interaction{
			Protocol:   "http",
			RemoteAddr: r.RemoteAddr,
			Path:       r.URL.Path,
			At:         it.now(),
		})
		it.mu.Unlock()
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func tokenFromPath(path string) string {
	for _, seg := range strings.Split(path, "/") {
		if isToken(seg) {
			return seg
		}
	}
	return ""
}

func tokenFromHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, label := range strings.Split(host, ".") {
		if isToken(label) {
			return label
		}
	}
	return ""
}

func isToken(s string) bool {
	if len(s) != tokenLen {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'f') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

const tokenLen = 32

func (it *Interactor) NewSession() (token, callbackURL string) {
	raw := make([]byte, tokenLen/2)
	if _, err := rand.Read(raw); err != nil {
		for i := range raw {
			raw[i] = byte(i)
		}
	}
	token = hex.EncodeToString(raw)
	callbackURL = it.host + "/" + token
	return token, callbackURL
}

func (it *Interactor) Poll(token string) []Interaction {
	it.mu.Lock()
	defer it.mu.Unlock()
	out := make([]Interaction, len(it.hits[token]))
	copy(out, it.hits[token])
	return out
}

func (it *Interactor) Host() string {
	return it.host
}

func (it *Interactor) Close() error {
	return it.server.Close()
}
