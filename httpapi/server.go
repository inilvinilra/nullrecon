package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/providers/registry"
)

type Server struct {
	db       *database.DB
	registry *registry.Registry
	now      func() time.Time
}

func NewServer(db *database.DB, reg *registry.Registry) *Server {
	return &Server{db: db, registry: reg, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/projects", s.guard(identity.RoleViewer, s.handleProjects))
	mux.HandleFunc("GET /api/v1/projects/{slug}", s.guard(identity.RoleViewer, s.handleProject))
	mux.HandleFunc("GET /api/v1/projects/{slug}/findings", s.guard(identity.RoleViewer, s.handleFindings))
	mux.HandleFunc("GET /api/v1/projects/{slug}/exposures", s.guard(identity.RoleViewer, s.handleExposures))
	mux.HandleFunc("GET /api/v1/projects/{slug}/vulnerabilities", s.guard(identity.RoleViewer, s.handleVulnerabilities))
	mux.HandleFunc("GET /api/v1/projects/{slug}/report", s.guard(identity.RoleViewer, s.handleReport))
	mux.HandleFunc("GET /api/v1/services", s.guard(identity.RoleViewer, s.handleServices))
	mux.HandleFunc("GET /api/v1/cve/stats", s.guard(identity.RoleViewer, s.handleCVEStats))
	mux.HandleFunc("GET /", s.handleUI)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) guard(min identity.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := s.authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid api key")
			return
		}
		if !roleSatisfies(key.Role, min) {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		next(w, r)
	}
}

func (s *Server) authenticate(r *http.Request) (identity.APIKey, bool) {
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	if token == "" {
		return identity.APIKey{}, false
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	key, found, err := s.db.APIKeys().ByHash(r.Context(), hash)
	if err != nil || !found || key.Revoked {
		return identity.APIKey{}, false
	}
	_ = s.db.APIKeys().TouchUsed(r.Context(), key.ID, s.now())
	return key, true
}

func roleSatisfies(have, min identity.Role) bool {
	rank := map[identity.Role]int{identity.RoleViewer: 1, identity.RoleOperator: 2, identity.RoleAdmin: 3}
	return rank[have] >= rank[min] && rank[have] > 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) project(ctx context.Context, w http.ResponseWriter, slug string) (string, bool) {
	project, err := s.db.Projects().BySlug(ctx, slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return "", false
	}
	return project.ID, true
}
