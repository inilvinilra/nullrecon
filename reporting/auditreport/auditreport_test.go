package auditreport

import (
	"strings"
	"testing"
	"time"
)

func TestMarkdownOrdersBySeverityAndAddsRemediation(t *testing.T) {
	r := Report{
		Title:       "Test Audit",
		GeneratedAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		Scope:       []string{"127.0.0.1"},
		Findings: []Finding{
			{ID: "spf-missing", Severity: "low", Target: "example.com", Detail: "no spf"},
			{ID: "redis-unauthenticated-access", Severity: "critical", Target: "127.0.0.1:6379", Confirmed: true, Evidence: "redis_version:7.4.5"},
		},
	}
	md := Markdown(r)
	critAt := strings.Index(md, "redis-unauthenticated-access")
	lowAt := strings.Index(md, "spf-missing")
	if critAt < 0 || lowAt < 0 || critAt > lowAt {
		t.Fatalf("critical must render before low; crit=%d low=%d", critAt, lowAt)
	}
	if !strings.Contains(md, "CONFIRMED") {
		t.Fatal("confirmed finding must be marked CONFIRMED")
	}
	if !strings.Contains(md, "requirepass") {
		t.Fatal("redis remediation must be injected by ID")
	}
	if !strings.Contains(md, "1 actively confirmed") {
		t.Fatalf("summary must count confirmed findings:\n%s", md)
	}
}

func TestMarkdownEmpty(t *testing.T) {
	md := Markdown(Report{GeneratedAt: time.Now()})
	if !strings.Contains(md, "No findings") {
		t.Fatal("empty report must say no findings")
	}
}
