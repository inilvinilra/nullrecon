package template

import (
	"regexp"
	"strconv"
	"strings"
)

type dslValue struct {
	s    string
	i    int
	b    bool
	kind byte
}

func dslStr(s string) dslValue { return dslValue{s: s, kind: 's'} }
func dslInt(i int) dslValue    { return dslValue{i: i, kind: 'i'} }
func dslBool(b bool) dslValue  { return dslValue{b: b, kind: 'b'} }

func (v dslValue) asString() string {
	switch v.kind {
	case 'i':
		return strconv.Itoa(v.i)
	case 'b':
		return strconv.FormatBool(v.b)
	default:
		return v.s
	}
}

func (v dslValue) asBool() bool {
	switch v.kind {
	case 'b':
		return v.b
	case 'i':
		return v.i != 0
	default:
		return v.s != ""
	}
}

type dslParser struct {
	toks []string
	pos  int
	view responseView
	ok   bool
}

func evalDSL(expr string, view responseView) (bool, bool) {
	p := &dslParser{toks: tokenizeDSL(expr), view: view, ok: true}
	if len(p.toks) == 0 {
		return false, false
	}
	val := p.parseOr()
	if !p.ok || p.pos != len(p.toks) {
		return false, false
	}
	return val.asBool(), true
}

func tokenizeDSL(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '"' || c == '\'':
			q := c
			j := i + 1
			var sb strings.Builder
			for j < len(s) && s[j] != q {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				sb.WriteByte(s[j])
				j++
			}
			toks = append(toks, "\x00"+sb.String())
			i = j + 1
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, "&&")
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, "||")
			i += 2
		case (c == '=' || c == '!' || c == '>' || c == '<') && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, s[i:i+2])
			i += 2
		case c == '(' || c == ')' || c == ',' || c == '!' || c == '>' || c == '<':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n\"'(),&|=!><", rune(s[j])) {
				j++
			}
			if j > i {
				toks = append(toks, s[i:j])
				i = j
			} else {
				i++
			}
		}
	}
	return toks
}

func (p *dslParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *dslParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *dslParser) parseOr() dslValue {
	left := p.parseAnd()
	for p.peek() == "||" {
		p.next()
		right := p.parseAnd()
		left = dslBool(left.asBool() || right.asBool())
	}
	return left
}

func (p *dslParser) parseAnd() dslValue {
	left := p.parseNot()
	for p.peek() == "&&" {
		p.next()
		right := p.parseNot()
		left = dslBool(left.asBool() && right.asBool())
	}
	return left
}

func (p *dslParser) parseNot() dslValue {
	if p.peek() == "!" {
		p.next()
		return dslBool(!p.parseNot().asBool())
	}
	return p.parseComparison()
}

func (p *dslParser) parseComparison() dslValue {
	left := p.parsePrimary()
	op := p.peek()
	switch op {
	case "==", "!=", ">", "<", ">=", "<=":
		p.next()
		right := p.parsePrimary()
		return dslBool(compareDSL(left, right, op))
	}
	return left
}

func compareDSL(a, b dslValue, op string) bool {
	if a.kind == 'i' || b.kind == 'i' {
		ai, aerr := strconv.Atoi(a.asString())
		bi, berr := strconv.Atoi(b.asString())
		if aerr == nil && berr == nil {
			switch op {
			case "==":
				return ai == bi
			case "!=":
				return ai != bi
			case ">":
				return ai > bi
			case "<":
				return ai < bi
			case ">=":
				return ai >= bi
			case "<=":
				return ai <= bi
			}
		}
	}
	as, bs := a.asString(), b.asString()
	switch op {
	case "==":
		return as == bs
	case "!=":
		return as != bs
	case ">":
		return as > bs
	case "<":
		return as < bs
	case ">=":
		return as >= bs
	case "<=":
		return as <= bs
	}
	return false
}

func (p *dslParser) parsePrimary() dslValue {
	t := p.next()
	if strings.HasPrefix(t, "\x00") {
		return dslStr(t[1:])
	}
	if t == "(" {
		v := p.parseOr()
		if p.peek() == ")" {
			p.next()
		}
		return v
	}
	if n, err := strconv.Atoi(t); err == nil {
		return dslInt(n)
	}
	if p.peek() == "(" {
		return p.parseFunc(t)
	}
	switch t {
	case "body", "body_1", "data":
		return dslStr(p.view.body)
	case "all", "raw":
		return dslStr(p.view.part("all"))
	case "header", "all_headers":
		return dslStr(p.view.headerText)
	case "content_type":
		return dslStr(p.view.headers["content-type"])
	case "status_code":
		return dslInt(p.view.status)
	case "true":
		return dslBool(true)
	case "false":
		return dslBool(false)
	}
	p.ok = false
	return dslStr("")
}

func (p *dslParser) parseFunc(name string) dslValue {
	p.next()
	var args []dslValue
	for p.peek() != ")" && p.peek() != "" {
		args = append(args, p.parseOr())
		if p.peek() == "," {
			p.next()
		}
	}
	if p.peek() == ")" {
		p.next()
	}
	return p.callFunc(name, args)
}

func (p *dslParser) callFunc(name string, args []dslValue) dslValue {
	switch name {
	case "contains":
		if len(args) >= 2 {
			return dslBool(strings.Contains(args[0].asString(), args[1].asString()))
		}
	case "contains_all":
		if len(args) >= 2 {
			hay := args[0].asString()
			for _, a := range args[1:] {
				if !strings.Contains(hay, a.asString()) {
					return dslBool(false)
				}
			}
			return dslBool(true)
		}
	case "contains_any":
		if len(args) >= 2 {
			hay := args[0].asString()
			for _, a := range args[1:] {
				if strings.Contains(hay, a.asString()) {
					return dslBool(true)
				}
			}
			return dslBool(false)
		}
	case "tolower", "to_lower":
		if len(args) == 1 {
			return dslStr(strings.ToLower(args[0].asString()))
		}
	case "toupper", "to_upper":
		if len(args) == 1 {
			return dslStr(strings.ToUpper(args[0].asString()))
		}
	case "len":
		if len(args) == 1 {
			return dslInt(len(args[0].asString()))
		}
	case "trim", "trim_space":
		if len(args) == 1 {
			return dslStr(strings.TrimSpace(args[0].asString()))
		}
	case "regex":
		if len(args) >= 2 {
			re, err := regexp.Compile(args[0].asString())
			if err != nil {
				p.ok = false
				return dslBool(false)
			}
			return dslBool(re.MatchString(args[1].asString()))
		}
	case "compare_versions":
		if len(args) >= 2 {
			v := parseVer(args[0].asString())
			for _, c := range args[1:] {
				if !versionConstraintOK(v, c.asString()) {
					return dslBool(false)
				}
			}
			return dslBool(true)
		}
	case "status_code":
		return dslInt(p.view.status)
	}
	p.ok = false
	return dslBool(false)
}

type verParts []int

func parseVer(s string) verParts {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	var out verParts
	for _, f := range strings.Split(s, ".") {
		n := 0
		for i := 0; i < len(f) && f[i] >= '0' && f[i] <= '9'; i++ {
			n = n*10 + int(f[i]-'0')
		}
		out = append(out, n)
	}
	return out
}

func cmpVer(a, b verParts) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionConstraintOK(v verParts, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	op := ""
	for _, o := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if strings.HasPrefix(constraint, o) {
			op = o
			constraint = strings.TrimSpace(constraint[len(o):])
			break
		}
	}
	if op == "" {
		op = "=="
	}
	c := cmpVer(v, parseVer(constraint))
	switch op {
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case "==":
		return c == 0
	case "!=":
		return c != 0
	}
	return false
}
