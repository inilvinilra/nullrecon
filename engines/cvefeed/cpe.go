package cvefeed

import "strings"

func parseCPE(criteria string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(criteria, "cpe:2.3:") {
		return "", "", false
	}
	fields := splitCPE(criteria)
	if len(fields) < 5 {
		return "", "", false
	}
	vendor = unescapeCPE(fields[3])
	product = unescapeCPE(fields[4])
	if product == "" || product == "*" || product == "-" {
		return "", "", false
	}
	return vendor, product, true
}

func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			cur.WriteRune(r)
			escaped = true
			continue
		}
		if r == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	out = append(out, cur.String())
	return out
}

func unescapeCPE(s string) string {
	s = strings.ReplaceAll(s, "\\", "")
	return strings.ToLower(s)
}
