package fingerprint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/technology"
)

type RuleSet struct {
	contracts.Versioned
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Product string  `json:"product"`
	Vendor  string  `json:"vendor,omitempty"`
	CPE     string  `json:"cpe,omitempty"`
	Weight  float64 `json:"weight"`
	Match   Match   `json:"match"`
}

type Match struct {
	HeaderName  string `json:"headerName,omitempty"`
	HeaderValue string `json:"headerValue,omitempty"`
	Body        string `json:"body,omitempty"`
	Title       string `json:"title,omitempty"`
	Cookie      string `json:"cookie,omitempty"`
	FaviconMMH3 *int32 `json:"faviconMmh3,omitempty"`
	TLSIssuer   string `json:"tlsIssuer,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

type Features struct {
	Headers     map[string]string `json:"headers,omitempty"`
	Cookies     []string          `json:"cookies,omitempty"`
	Title       string            `json:"title,omitempty"`
	BodySnippet string            `json:"bodySnippet,omitempty"`
	FaviconMMH3 *int32            `json:"faviconMmh3,omitempty"`
	TLSIssuer   string            `json:"tlsIssuer,omitempty"`
	Banner      string            `json:"banner,omitempty"`
}

type Compiled struct {
	name string
	rule Rule
	re   *regexp.Regexp
}

type Engine struct {
	sets     []RuleSet
	compiled []Compiled
}

func NewEngine(sets ...RuleSet) (*Engine, error) {
	e := &Engine{}
	for _, set := range sets {
		if set.Version != contracts.RuleSetV1 {
			return nil, fmt.Errorf("fingerprint: unsupported ruleset version %q", set.Version)
		}
		e.sets = append(e.sets, set)
		for _, rule := range set.Rules {
			if rule.Product == "" || rule.Weight <= 0 {
				return nil, fmt.Errorf("fingerprint: invalid rule for %q", rule.Product)
			}
			pattern := firstPattern(rule.Match)
			if pattern == "" && rule.Match.FaviconMMH3 == nil && rule.Match.Cookie == "" {
				return nil, fmt.Errorf("fingerprint: rule %s has no matcher", rule.Product)
			}
			var re *regexp.Regexp
			var err error
			if pattern != "" {
				re, err = regexp.Compile("(?i)" + pattern)
				if err != nil {
					return nil, fmt.Errorf("fingerprint: rule %s: %w", rule.Product, err)
				}
			}
			name := fmt.Sprintf("%s/%s", set.Name, rule.Product)
			e.compiled = append(e.compiled, Compiled{name: name, rule: rule, re: re})
		}
	}
	return e, nil
}

func firstPattern(m Match) string {
	for _, p := range []string{m.HeaderValue, m.Body, m.Title, m.TLSIssuer, m.Banner} {
		if p != "" {
			return p
		}
	}
	return ""
}

func (e *Engine) Apply(f Features) []technology.Technology {
	scores := map[string]*technology.Technology{}
	for _, c := range e.compiled {
		detail, ok := matchRule(c, f)
		if !ok {
			continue
		}
		tech, exists := scores[c.rule.Product]
		if !exists {
			tech = &technology.Technology{
				Product: c.rule.Product,
				Vendor:  c.rule.Vendor,
				Method:  "fingerprint",
			}
			if c.rule.CPE != "" {
				tech.CPE = []string{c.rule.CPE}
			}
			scores[c.rule.Product] = tech
		}
		tech.Confidence += c.rule.Weight
		tech.Evidence = append(tech.Evidence, technology.EvidenceRef{Kind: detail.kind, Detail: detail.text, Weight: c.rule.Weight})
		if version := extractVersion(c.re, detail.text); version != "" && tech.Version == "" {
			tech.Version = version
		}
	}
	var out []technology.Technology
	for _, tech := range scores {
		if tech.Confidence > 1 {
			tech.Confidence = 1
		}
		out = append(out, *tech)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

type matchDetail struct {
	kind string
	text string
}

func matchRule(c Compiled, f Features) (matchDetail, bool) {
	m := c.rule.Match
	if m.FaviconMMH3 != nil {
		if f.FaviconMMH3 == nil || *f.FaviconMMH3 != *m.FaviconMMH3 {
			return matchDetail{}, false
		}
		return matchDetail{"favicon", fmt.Sprintf("mmh3 %d", *m.FaviconMMH3)}, true
	}
	if m.Cookie != "" {
		for _, cookie := range f.Cookies {
			if strings.HasPrefix(strings.ToLower(cookie), strings.ToLower(m.Cookie)) {
				return matchDetail{"cookie", cookie}, true
			}
		}
		return matchDetail{}, false
	}
	if m.HeaderName != "" {
		value := f.Headers[strings.ToLower(m.HeaderName)]
		if value == "" {
			return matchDetail{}, false
		}
		if c.re != nil && m.HeaderValue != "" {
			if !c.re.MatchString(value) {
				return matchDetail{}, false
			}
		}
		return matchDetail{"header", value}, true
	}
	if m.Title != "" {
		if c.re.MatchString(f.Title) {
			return matchDetail{"title", f.Title}, true
		}
		return matchDetail{}, false
	}
	if m.Body != "" {
		if match := c.re.FindString(f.BodySnippet); match != "" {
			if len(match) > 160 {
				match = match[:160]
			}
			return matchDetail{"body", match}, true
		}
		if c.re.MatchString(f.BodySnippet) {
			return matchDetail{"body", ""}, true
		}
		return matchDetail{}, false
	}
	if m.TLSIssuer != "" {
		if c.re.MatchString(f.TLSIssuer) {
			return matchDetail{"tls", f.TLSIssuer}, true
		}
		return matchDetail{}, false
	}
	if m.Banner != "" {
		if c.re.MatchString(f.Banner) {
			return matchDetail{"banner", f.Banner}, true
		}
		return matchDetail{}, false
	}
	return matchDetail{}, false
}

var versionPattern = regexp.MustCompile(`([0-9]+\.[0-9]+(\.[0-9]+){0,2}[a-z]?)`)

func extractVersion(re *regexp.Regexp, text string) string {
	if re == nil || text == "" {
		return ""
	}
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		if v := versionPattern.FindString(m[len(m)-1]); v != "" {
			return v
		}
	}
	if v := versionPattern.FindString(text); v != "" && re.MatchString(text) && strings.Contains(text, v) {
		return v
	}
	return ""
}
