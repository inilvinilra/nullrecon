package template

import (
	"regexp"
	"strings"
)

type responseView struct {
	status     int
	body       string
	headerText string
	headers    map[string]string
}

func newResponseView(status int, body []byte, headers map[string]string) responseView {
	var sb strings.Builder
	lowerHeaders := map[string]string{}
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\n")
		lowerHeaders[strings.ToLower(k)] = v
	}
	return responseView{status: status, body: string(body), headerText: sb.String(), headers: lowerHeaders}
}

func (v responseView) part(name string) string {
	switch name {
	case "header", "headers":
		return v.headerText
	case "all":
		return v.headerText + "\n" + v.body
	default:
		return v.body
	}
}

func (m Matcher) evaluate(v responseView) bool {
	result := m.evaluateRaw(v)
	if m.Negative {
		return !result
	}
	return result
}

func (m Matcher) evaluateRaw(v responseView) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if v.status == s {
				return true
			}
		}
		return false
	case "word":
		return matchWords(v.part(partOr(m.Part, "body")), m.Words, m.Condition)
	case "regex":
		return matchRegexes(v.part(partOr(m.Part, "body")), m.compiled, m.Condition)
	case "header":
		if m.Header != "" {
			value, ok := v.headers[strings.ToLower(m.Header)]
			if !ok {
				return false
			}
			if len(m.Words) == 0 && len(m.compiled) == 0 {
				return true
			}
			if len(m.compiled) > 0 {
				return matchRegexes(value, m.compiled, m.Condition)
			}
			return matchWords(value, m.Words, m.Condition)
		}
		return matchWords(v.headerText, m.Words, m.Condition)
	}
	return false
}

func partOr(part, fallback string) string {
	if part == "" {
		return fallback
	}
	return part
}

func matchWords(text string, words []string, condition string) bool {
	if len(words) == 0 {
		return false
	}
	if condition == "or" {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}
	for _, w := range words {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

func matchRegexes(text string, regexes []*regexp.Regexp, condition string) bool {
	if len(regexes) == 0 {
		return false
	}
	if condition == "or" {
		for _, re := range regexes {
			if re.MatchString(text) {
				return true
			}
		}
		return false
	}
	for _, re := range regexes {
		if !re.MatchString(text) {
			return false
		}
	}
	return true
}

func (r Request) matches(v responseView) bool {
	if len(r.Matchers) == 0 {
		return false
	}
	if r.MatchersCondition == "or" {
		for _, m := range r.Matchers {
			if m.evaluate(v) {
				return true
			}
		}
		return false
	}
	for _, m := range r.Matchers {
		if !m.evaluate(v) {
			return false
		}
	}
	return true
}

func (r Request) extract(v responseView) map[string][]string {
	if len(r.Extractors) == 0 {
		return nil
	}
	out := map[string][]string{}
	for _, e := range r.Extractors {
		text := v.part(partOr(e.Part, "body"))
		group := e.Group
		if group == 0 {
			group = 1
		}
		for _, re := range e.compiled {
			for _, sm := range re.FindAllStringSubmatch(text, -1) {
				if group < len(sm) {
					out[e.Name] = append(out[e.Name], sm[group])
				} else if len(sm) > 0 {
					out[e.Name] = append(out[e.Name], sm[0])
				}
			}
		}
	}
	return out
}
