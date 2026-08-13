package redaction

import (
	"fmt"
	"regexp"
	"strings"
)

type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

func DefaultRules() []Rule {
	return []Rule{
		{Name: "authorization-header", Pattern: `(?i)(authorization|proxy-authorization)\s*[:=]\s*[^\n]+`, Replace: "$1=[REDACTED]"},
		{Name: "bearer-token", Pattern: `(?i)bearer\s+[a-z0-9._\-]+`, Replace: "Bearer [REDACTED]"},
		{Name: "cookie", Pattern: `(?i)(cookie|set-cookie)\s*[:=]\s*[^\n]+`, Replace: "$1=[REDACTED]"},
		{Name: "aws-access-key", Pattern: `\b(AKIA|ASIA)[A-Z0-9]{16}\b`, Replace: "[REDACTED-AWS-KEY]"},
		{Name: "generic-api-key", Pattern: `(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*\"?[^\s\",']{8,}`, Replace: "$1=[REDACTED]"},
		{Name: "private-key-block", Pattern: `-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*-----END [A-Z ]*PRIVATE KEY-----`, Replace: "[REDACTED-PRIVATE-KEY]"},
		{Name: "password-field", Pattern: `(?i)(password|passwd|pwd)\s*[:=]\s*\"?[^\s\",']{4,}`, Replace: "$1=[REDACTED]"},
		{Name: "email", Pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`, Replace: "[REDACTED-EMAIL]"},
		{Name: "query-credential", Pattern: `(?i)([?&](token|key|sig|signature|password|secret)=)[^&\s]+`, Replace: "$1[REDACTED]"},
	}
}

type Redactor struct {
	rules []compiledRule
}

type compiledRule struct {
	name    string
	pattern *regexp.Regexp
	replace string
}

func New(extra []Rule) (*Redactor, error) {
	all := append(DefaultRules(), extra...)
	var compiled []compiledRule
	for _, r := range all {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("redaction: rule %s: %w", r.Name, err)
		}
		compiled = append(compiled, compiledRule{name: r.Name, pattern: re, replace: r.Replace})
	}
	return &Redactor{rules: compiled}, nil
}

type Result struct {
	Text    string   `json:"text"`
	Matched []string `json:"matched"`
}

func (r *Redactor) Redact(input string) Result {
	matched := map[string]bool{}
	out := input
	for _, rule := range r.rules {
		if rule.pattern.MatchString(out) {
			matched[rule.name] = true
			out = rule.pattern.ReplaceAllString(out, rule.replace)
		}
	}
	var names []string
	for name := range matched {
		names = append(names, name)
	}
	return Result{Text: out, Matched: names}
}

var sensitiveKeys = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"x-auth-token":        true,
}

func (r *Redactor) RedactMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for k, v := range input {
		if sensitiveKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = r.Redact(v).Text
	}
	return out
}
