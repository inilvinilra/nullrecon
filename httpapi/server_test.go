package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/platform/database"
)

func setup(t *testing.T) (*Server, string, string) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	project := identity.NewProject("Acme", "acme")
	if err := db.Projects().Put(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	fnd := finding.Finding{
		ID: "fnd-1", ProjectID: project.ID, Title: "Exposed .git", State: finding.StateConfirmed,
		Severity: finding.SevHigh, Confidence: finding.Confidence{Value: 0.9}, FingerprintKey: "exposure:git:1",
		FirstSeen: now, LastSeen: now,
	}
	if err := db.Findings().Upsert(ctx, fnd); err != nil {
		t.Fatal(err)
	}
	secret := "nrk_testsecret"
	sum := sha256.Sum256([]byte(secret))
	key := identity.APIKey{ID: contracts.NewID("key"), Name: "test", KeyHash: hex.EncodeToString(sum[:]), Role: identity.RoleViewer, CreatedAt: now}
	if err := db.APIKeys().Put(ctx, key); err != nil {
		t.Fatal(err)
	}
	return NewServer(db, nil), secret, project.Slug
}

func TestUnauthorizedWithoutKey(t *testing.T) {
	srv, _, slug := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/projects/"+slug+"/findings", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", rec.Code)
	}
}

func TestUnauthorizedWithBadKey(t *testing.T) {
	srv, _, slug := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/projects/"+slug+"/findings", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad key, got %d", rec.Code)
	}
}

func TestFindingsWithValidKey(t *testing.T) {
	srv, secret, slug := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/projects/"+slug+"/findings", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid key, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Count    int `json:"count"`
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 1 || body.Findings[0].Title != "Exposed .git" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRevokedKeyRejected(t *testing.T) {
	srv, secret, slug := setup(t)
	keys, _ := srv.db.APIKeys().List(context.Background())
	if err := srv.db.APIKeys().Revoke(context.Background(), keys[0].ID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/projects/"+slug+"/findings", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key must be rejected, got %d", rec.Code)
	}
}

func TestHealthNoAuth(t *testing.T) {
	srv, _, _ := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health must be public, got %d", rec.Code)
	}
}

func TestUIServed(t *testing.T) {
	srv, _, _ := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected html UI, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
