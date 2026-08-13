package scopeguard

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/domain/asset"
)

type Target struct {
	Host     string `json:"host,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Path     string `json:"path,omitempty"`
}

type Decision struct {
	Allowed bool        `json:"allowed"`
	Class   asset.Class `json:"class"`
	Reasons []string    `json:"reasons"`
}

func (d Decision) deny(reason string) Decision {
	d.Allowed = false
	d.Reasons = append(d.Reasons, reason)
	return d
}

func (s Snapshot) Evaluate(t Target, now time.Time) Decision {
	d := Decision{Allowed: false, Class: asset.ClassUnknown}
	host := normalizeDomain(t.Host)
	ip := t.IP
	if ip == "" && host != "" {
		if addr, err := netip.ParseAddr(host); err == nil {
			ip = addr.String()
			host = ""
		}
	}
	if host == "" && ip == "" {
		return d.deny("target has neither host nor ip")
	}
	if !withinWindows(s.Scope.TimeWindows, now.UTC()) {
		return d.deny("outside authorized time windows")
	}
	if denied, reason := s.matchesDenied(host, ip, t.Path); denied {
		d.Class = asset.ClassDenied
		return d.deny(reason)
	}
	if !s.inScope(host, ip) {
		return d.deny("target does not match any allowed domain, ip, cidr, or url prefix")
	}
	if reason, ok := s.portAllowed(t.Port, t.Protocol); !ok {
		return d.deny(reason)
	}
	d.Allowed = true
	d.Class = asset.ClassActive
	d.Reasons = append(d.Reasons, "target matches compiled scope")
	return d
}

func (s Snapshot) EvaluateAction(t Target, action policy.ActionClass, now time.Time) Decision {
	d := s.Evaluate(t, now)
	if !d.Allowed {
		return d
	}
	if s.Scope.DeniesAction(string(action)) {
		return d.deny(fmt.Sprintf("action %s is explicitly denied by scope", action))
	}
	granted := s.Scope.Grants(string(action))
	pd := policy.Decide(s.Mode, action, granted)
	if !pd.Allowed {
		return d.deny(pd.Reasons[0])
	}
	d.Reasons = append(d.Reasons, pd.Reasons...)
	return d
}

func (s Snapshot) EvaluatePivot(from, to Target, now time.Time) Decision {
	d := s.Evaluate(to, now)
	d.Reasons = append([]string{fmt.Sprintf("pivot from %s to %s re-evaluated against scope", pivotLabel(from), pivotLabel(to))}, d.Reasons...)
	return d
}

func pivotLabel(t Target) string {
	if t.Host != "" {
		return t.Host
	}
	return t.IP
}

func (s Snapshot) matchesDenied(host, ip, path string) (bool, string) {
	for _, denied := range s.Scope.DeniedAssets {
		if host != "" && hostMatches(denied, host) {
			return true, fmt.Sprintf("host %s matches denied asset %s", host, denied)
		}
		if ip != "" {
			if addr, err := netip.ParseAddr(ip); err == nil {
				if prefix, perr := netip.ParsePrefix(denied); perr == nil && prefix.Contains(addr) {
					return true, fmt.Sprintf("ip %s matches denied range %s", ip, denied)
				}
				if denied == addr.String() {
					return true, fmt.Sprintf("ip %s is explicitly denied", ip)
				}
			}
		}
	}
	for _, dp := range s.Scope.DeniedPaths {
		if path != "" && strings.HasPrefix(path, dp) {
			return true, fmt.Sprintf("path %s matches denied path prefix %s", path, dp)
		}
	}
	return false, ""
}

func (s Snapshot) inScope(host, ip string) bool {
	for _, exact := range s.Scope.ExactDomains {
		if host != "" && host == exact {
			return true
		}
	}
	for _, root := range s.Scope.RootDomains {
		if host != "" && hostMatches(root, host) {
			return true
		}
	}
	if ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil {
			for _, raw := range s.Scope.IPs {
				if raw == addr.String() {
					return true
				}
			}
			for _, raw := range s.Scope.CIDRs {
				if prefix, perr := netip.ParsePrefix(raw); perr == nil && prefix.Contains(addr) {
					return true
				}
			}
		}
	}
	for _, prefix := range s.Scope.URLPrefixes {
		if host != "" && strings.Contains(prefix, "://"+host) {
			return true
		}
	}
	return false
}

func hostMatches(allowed, host string) bool {
	if allowed == host {
		return true
	}
	return strings.HasSuffix(host, "."+allowed)
}

func (s Snapshot) portAllowed(port int, protocol string) (string, bool) {
	if port != 0 {
		if len(s.Scope.Ports) == 0 {
			return fmt.Sprintf("port %d requested but scope allows no explicit ports", port), false
		}
		found := false
		for _, p := range s.Scope.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("port %d is outside the allowed port list", port), false
		}
	}
	if protocol != "" && len(s.Scope.Protocols) > 0 {
		for _, p := range s.Scope.Protocols {
			if p == protocol {
				return "", true
			}
		}
		return fmt.Sprintf("protocol %s is outside the allowed protocol list", protocol), false
	}
	return "", true
}
