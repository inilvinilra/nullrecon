package normalize

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/nullrecon/nullrecon/domain/asset"
)

var hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func Host(value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimPrefix(v, "*.")
	if v == "" {
		return "", fmt.Errorf("normalize: empty host")
	}
	if ip, err := IP(v); err == nil {
		return ip, nil
	}
	if !hostPattern.MatchString(v) {
		return "", fmt.Errorf("normalize: invalid host %q", value)
	}
	return v, nil
}

func IP(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("normalize: invalid ip %q", value)
	}
	return addr.String(), nil
}

func URL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("normalize: invalid url %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("normalize: unsupported scheme %q", u.Scheme)
	}
	host, err := Host(u.Hostname())
	if err != nil {
		return "", err
	}
	port := u.Port()
	defaultPort := (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443")
	if port == "" || defaultPort {
		u.Host = host
	} else {
		u.Host = host + ":" + port
	}
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err == nil {
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var pairs []string
			for _, k := range keys {
				vals := append([]string{}, values[k]...)
				sort.Strings(vals)
				for _, v := range vals {
					pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
				}
			}
			u.RawQuery = strings.Join(pairs, "&")
		}
	}
	return u.String(), nil
}

func KindForValue(value string) (asset.Kind, error) {
	v := strings.TrimSpace(strings.ToLower(value))
	if _, err := netip.ParseAddr(v); err == nil {
		return asset.KindIP, nil
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return asset.KindCIDR, nil
	}
	if strings.Contains(v, "://") {
		if _, err := URL(v); err == nil {
			return asset.KindURLRoot, nil
		}
		return "", fmt.Errorf("normalize: invalid url %q", value)
	}
	if hostPattern.MatchString(strings.TrimSuffix(v, ".")) {
		parts := strings.Split(strings.TrimSuffix(v, "."), ".")
		if len(parts) > 2 {
			return asset.KindHostname, nil
		}
		return asset.KindDomain, nil
	}
	return "", fmt.Errorf("normalize: cannot classify %q", value)
}

func ParentDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func Identity(kind asset.Kind, value string) string {
	return string(kind) + "|" + value
}
