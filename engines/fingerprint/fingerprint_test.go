package fingerprint

import (
	"encoding/json"
	"os"
	"testing"
)

func loadBaseline(t *testing.T) RuleSet {
	t.Helper()
	data, err := os.ReadFile("../../rules/fingerprint.json")
	if err != nil {
		t.Fatal(err)
	}
	var set RuleSet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	return set
}

func TestBaselineRulesetLoads(t *testing.T) {
	set := loadBaseline(t)
	if _, err := NewEngine(set); err != nil {
		t.Fatalf("baseline ruleset must compile: %v", err)
	}
}

func TestMMH3KnownVector(t *testing.T) {
	if got := MMH3([]byte("")); got != 0 {
		t.Fatalf("empty input must hash to 0, got %d", got)
	}
	if got := MMH3([]byte("hello")); got != 613153351 {
		t.Fatalf("mmh3('hello') must be 613153351, got %d", got)
	}
	if got := FaviconMMH3([]byte("favicon")); got == 0 {
		t.Fatal("favicon hash must be computed")
	}
}

func TestHeaderMatch(t *testing.T) {
	e, err := NewEngine(loadBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	got := e.Apply(Features{Headers: map[string]string{"server": "nginx/1.25.0"}})
	if len(got) == 0 || got[0].Product != "nginx" {
		t.Fatalf("nginx must be detected: %+v", got)
	}
	if got[0].Version != "1.25.0" {
		t.Fatalf("version must be extracted: %+v", got[0])
	}
	if got[0].CPE[0] != "cpe:/a:f5:nginx" {
		t.Fatalf("cpe candidate must be attached: %+v", got[0].CPE)
	}
	if len(got[0].Evidence) == 0 {
		t.Fatal("evidence components must be attached")
	}
}

func TestMultipleSignalsAggregate(t *testing.T) {
	e, _ := NewEngine(loadBaseline(t))
	got := e.Apply(Features{
		BodySnippet: `<script src="/wp-content/themes/x/jquery-3.7.min.js"></script>`,
		Cookies:     []string{"wordpress_test=1", "other=1"},
	})
	byProduct := map[string]float64{}
	for _, tech := range got {
		byProduct[tech.Product] = tech.Confidence
	}
	if byProduct["wordpress"] <= 0.6 {
		t.Fatalf("two wordpress signals must aggregate above single weight: %v", byProduct)
	}
	if byProduct["jQuery"] == 0 {
		t.Fatal("jquery must be detected from script tag")
	}
}

func TestNoMatchReturnsEmpty(t *testing.T) {
	e, _ := NewEngine(loadBaseline(t))
	got := e.Apply(Features{Headers: map[string]string{"server": "caddy"}, Title: "Hello"})
	if len(got) != 0 {
		t.Fatalf("unknown stack must yield no candidates: %+v", got)
	}
}

func TestInvalidRulesetRejected(t *testing.T) {
	if _, err := NewEngine(RuleSet{}); err == nil {
		t.Fatal("unversioned ruleset must be rejected")
	}
}

func TestBannerMatch(t *testing.T) {
	e, _ := NewEngine(loadBaseline(t))
	got := e.Apply(Features{Banner: "SSH-2.0-OpenSSH_9.6"})
	if len(got) == 0 || got[0].Product != "openssh" || got[0].Version != "9.6" {
		t.Fatalf("openssh banner must match with version: %+v", got)
	}
}
