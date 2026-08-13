package renderer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/domain/finding"
)

func sampleData() Data {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d := New("proj-1", "acme", now)
	d.RunID = "run-1"
	d.Mode = "authorizedtest"
	d.SnapshotHash = "abc123"
	d.ExposureCount = 2
	d.SecretSummary = map[string]int{"aws-access-key": 1}
	d.Findings = []finding.Finding{
		{
			ID: "fnd-1", Title: "Exposed .git/config", State: finding.StateConfirmed,
			Severity: finding.SevHigh, Confidence: finding.Confidence{Value: 0.95},
			AssetIDs: []string{"ast-1"}, WeaknessClass: "exposure:leak", SnapshotHash: "abc123",
			FirstSeen: now, LastSeen: now,
		},
		{
			ID: "fnd-2", Title: "phpinfo exposed", State: finding.StateConfirmed,
			Severity: finding.SevMedium, Confidence: finding.Confidence{Value: 0.9},
			AssetIDs: []string{"ast-1"}, WeaknessClass: "exposure:exposure",
			FirstSeen: now, LastSeen: now,
		},
	}
	return d
}

func TestRenderJSONRoundTrips(t *testing.T) {
	data := sampleData()
	raw, err := RenderJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var back Data
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != 2 || back.ProjectSlug != "acme" {
		t.Fatalf("json report did not round-trip: %+v", back)
	}
}

func TestRenderMarkdown(t *testing.T) {
	out, err := RenderMarkdown(sampleData())
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"# nullrecon report", "## Summary", "Exposed .git/config", "abc123", "aws-access-key"} {
		if !strings.Contains(text, want) {
			t.Fatalf("markdown report missing %q:\n%s", want, text)
		}
	}
}

func TestRenderSARIF(t *testing.T) {
	out, err := RenderSARIF(sampleData())
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("sarif must be valid json: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("sarif version wrong: %v", log["version"])
	}
	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("sarif must have one run: %v", log["runs"])
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("sarif must carry one result per finding, got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["level"] != "error" {
		t.Fatalf("high severity must map to sarif error level, got %v", first["level"])
	}
}

func TestRenderSARIFEmpty(t *testing.T) {
	d := New("p", "s", time.Now())
	out, err := RenderSARIF(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\"results\": []") {
		t.Fatalf("empty report must still produce a valid results array:\n%s", out)
	}
}
