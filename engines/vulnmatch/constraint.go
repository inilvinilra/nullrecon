package vulnmatch

import "strings"

type comparator struct {
	op  string
	ver version
}

type constraint struct {
	comparators []comparator
	ok          bool
}

func parseConstraint(expr string) constraint {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) == 0 {
		return constraint{}
	}
	var comps []comparator
	for _, f := range fields {
		op, rest := splitOperator(f)
		v := parseVersion(rest)
		if !v.ok {
			return constraint{}
		}
		comps = append(comps, comparator{op: op, ver: v})
	}
	return constraint{comparators: comps, ok: true}
}

func splitOperator(f string) (string, string) {
	switch {
	case strings.HasPrefix(f, ">="):
		return ">=", f[2:]
	case strings.HasPrefix(f, "<="):
		return "<=", f[2:]
	case strings.HasPrefix(f, ">"):
		return ">", f[1:]
	case strings.HasPrefix(f, "<"):
		return "<", f[1:]
	case strings.HasPrefix(f, "="):
		return "=", f[1:]
	}
	return "=", f
}

func (c constraint) matches(v version) bool {
	if !c.ok || !v.ok {
		return false
	}
	for _, comp := range c.comparators {
		cmp := compareVersions(v, comp.ver)
		switch comp.op {
		case ">=":
			if cmp < 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "=":
			if cmp != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
