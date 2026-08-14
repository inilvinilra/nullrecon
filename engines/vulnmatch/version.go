package vulnmatch

import (
	"strconv"
	"strings"
)

type version struct {
	parts []int
	patch string
	pre   string
	ok    bool
}

func parseVersion(raw string) version {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return version{}
	}
	pre := ""
	if idx := strings.IndexAny(s, "-+"); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
	}
	fields := strings.Split(s, ".")
	parts := make([]int, 0, len(fields))
	patch := ""
	for i, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			return version{}
		}
		digits := leadingDigits(f)
		if digits == "" {
			return version{}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return version{}
		}
		parts = append(parts, n)
		if i == len(fields)-1 {
			patch = strings.ToLower(f[len(digits):])
		}
	}
	if len(parts) == 0 {
		return version{}
	}
	return version{parts: parts, patch: patch, pre: pre, ok: true}
}

var exchangeBuildYear = map[string]string{
	"8":    "2007",
	"14":   "2010",
	"15.0": "2013",
	"15.1": "2016",
	"15.2": "2019",
}

func normalizeVersion(product, raw string) string {
	v := parseVersion(raw)
	if !v.ok || len(v.parts) == 0 {
		return raw
	}
	switch strings.ToLower(strings.TrimSpace(product)) {
	case "exchange_server":
		major := strconv.Itoa(v.parts[0])
		if len(v.parts) >= 2 {
			if y, ok := exchangeBuildYear[major+"."+strconv.Itoa(v.parts[1])]; ok {
				return y
			}
		}
		if y, ok := exchangeBuildYear[major]; ok {
			return y
		}
	case "sharepoint_server":
		if len(v.parts) >= 2 {
			switch {
			case v.parts[0] == 12 && v.parts[1] == 0:
				return "2007"
			case v.parts[0] == 14 && v.parts[1] == 0:
				return "2010"
			case v.parts[0] == 15 && v.parts[1] == 0:
				return "2013"
			case v.parts[0] == 16 && v.parts[1] == 0:
				if len(v.parts) >= 3 && v.parts[2] >= 10000 {
					return "2019"
				}
				return "2016"
			}
		}
	}
	return raw
}

func leadingDigits(s string) string {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	return s[:end]
}

func compareVersions(a, b version) int {
	max := len(a.parts)
	if len(b.parts) > max {
		max = len(b.parts)
	}
	for i := 0; i < max; i++ {
		ai, bi := 0, 0
		if i < len(a.parts) {
			ai = a.parts[i]
		}
		if i < len(b.parts) {
			bi = b.parts[i]
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	if a.patch != b.patch {
		if a.patch == "" {
			return -1
		}
		if b.patch == "" {
			return 1
		}
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	if a.pre == b.pre {
		return 0
	}
	if a.pre == "" {
		return 1
	}
	if b.pre == "" {
		return -1
	}
	if a.pre < b.pre {
		return -1
	}
	return 1
}
