package template

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nullrecon/nullrecon/contracts"
)

//go:embed templates.json
var embeddedTemplates []byte

func LoadEmbedded() (*Set, error) {
	return Parse(embeddedTemplates)
}

type Info struct {
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Reference    []string `json:"reference,omitempty"`
	CVE          string   `json:"cve,omitempty"`
	CWE          string   `json:"cwe,omitempty"`
	Prerequisite bool     `json:"prerequisite,omitempty"`
	Reflection   bool     `json:"reflection,omitempty"`
}

type Matcher struct {
	Type      string   `json:"type"`
	Part      string   `json:"part,omitempty"`
	Words     []string `json:"words,omitempty"`
	Regexes   []string `json:"regex,omitempty"`
	Status    []int    `json:"status,omitempty"`
	Header    string   `json:"header,omitempty"`
	DSL       []string `json:"dsl,omitempty"`
	Condition string   `json:"condition,omitempty"`
	Negative  bool     `json:"negative,omitempty"`

	compiled []*regexp.Regexp
}

type Extractor struct {
	Type    string   `json:"type"`
	Part    string   `json:"part,omitempty"`
	Name    string   `json:"name"`
	Regexes []string `json:"regex,omitempty"`
	Group   int      `json:"group,omitempty"`

	compiled []*regexp.Regexp
}

type Request struct {
	Method            string            `json:"method"`
	Paths             []string          `json:"path"`
	Raw               []string          `json:"raw,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body,omitempty"`
	MatchersCondition string            `json:"matchersCondition,omitempty"`
	Matchers          []Matcher         `json:"matchers"`
	Extractors        []Extractor       `json:"extractors,omitempty"`
}

func parseRaw(raw string) (method, path string, headers map[string]string, body string, ok bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head := raw
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		head = raw[:idx]
		body = strings.TrimRight(raw[idx+2:], "\n")
	}
	lines := strings.Split(strings.TrimSpace(head), "\n")
	if len(lines) == 0 {
		return
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return
	}
	method = fields[0]
	path = fields[1]
	for _, pfx := range []string{"{{BaseURL}}", "{{RootURL}}"} {
		path = strings.TrimPrefix(path, pfx)
	}
	headers = map[string]string{}
	for _, l := range lines[1:] {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(l[:i])
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		headers[k] = strings.TrimSpace(l[i+1:])
	}
	ok = method != "" && strings.HasPrefix(path, "/")
	return
}

type Template struct {
	ID       string    `json:"id"`
	Info     Info      `json:"info"`
	Requests []Request `json:"requests"`
}

type Set struct {
	contracts.Versioned
	Templates []Template `json:"templates"`
}

func Parse(data []byte) (*Set, error) {
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("template: parse set: %w", err)
	}
	set.Kind = "templates"
	set.Version = contracts.RuleSetV1
	for i := range set.Templates {
		t := &set.Templates[i]
		if t.ID == "" || len(t.Requests) == 0 {
			return nil, fmt.Errorf("template: %q missing id or requests", t.ID)
		}
		for j := range t.Requests {
			r := &t.Requests[j]
			if len(r.Raw) > 0 {
				method, path, headers, body, ok := parseRaw(r.Raw[0])
				if !ok {
					return nil, fmt.Errorf("template: %q has an unparseable raw request", t.ID)
				}
				r.Method = method
				r.Paths = []string{path}
				if r.Headers == nil {
					r.Headers = headers
				}
				if r.Body == "" {
					r.Body = body
				}
			}
			if r.Method == "" {
				r.Method = "GET"
			}
			if len(r.Paths) == 0 {
				r.Paths = []string{"/"}
			}
			if len(r.Matchers) == 0 {
				return nil, fmt.Errorf("template: %q request has no matchers", t.ID)
			}
			for k := range r.Matchers {
				if err := compileMatcher(&r.Matchers[k], t.ID); err != nil {
					return nil, err
				}
			}
			for k := range r.Extractors {
				if err := compileExtractor(&r.Extractors[k], t.ID); err != nil {
					return nil, err
				}
			}
		}
	}
	return &set, nil
}

func compileMatcher(m *Matcher, id string) error {
	for _, expr := range m.Regexes {
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("template: %q matcher regex %q: %w", id, expr, err)
		}
		m.compiled = append(m.compiled, re)
	}
	switch m.Type {
	case "status", "word", "regex", "header", "dsl":
	default:
		return fmt.Errorf("template: %q unknown matcher type %q", id, m.Type)
	}
	return nil
}

func compileExtractor(e *Extractor, id string) error {
	if e.Name == "" {
		return fmt.Errorf("template: %q extractor missing name", id)
	}
	for _, expr := range e.Regexes {
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("template: %q extractor regex %q: %w", id, expr, err)
		}
		e.compiled = append(e.compiled, re)
	}
	return nil
}
