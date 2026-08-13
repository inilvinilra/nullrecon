package scopeguard

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/nullrecon/nullrecon/contracts"
)

var domainPattern = regexp.MustCompile(`^(\*\.|)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type RateLimit struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	RequestsPerMinute int     `json:"requestsPerMinute"`
}

type TimeWindow struct {
	StartUTC string `json:"startUtc"`
	EndUTC   string `json:"endUtc"`
}

type Scope struct {
	contracts.Versioned
	RootDomains         []string     `json:"rootDomains,omitempty"`
	ExactDomains        []string     `json:"exactDomains,omitempty"`
	IPs                 []string     `json:"ips,omitempty"`
	CIDRs               []string     `json:"cidrs,omitempty"`
	URLPrefixes         []string     `json:"urlPrefixes,omitempty"`
	Ports               []int        `json:"ports,omitempty"`
	Protocols           []string     `json:"protocols,omitempty"`
	TestAccounts        []string     `json:"testAccounts,omitempty"`
	ScanClasses         []string     `json:"scanClasses,omitempty"`
	VerificationClasses []string     `json:"verificationClasses,omitempty"`
	DeniedAssets        []string     `json:"deniedAssets,omitempty"`
	DeniedPaths         []string     `json:"deniedPaths,omitempty"`
	DeniedActions       []string     `json:"deniedActions,omitempty"`
	Rate                RateLimit    `json:"rateLimits"`
	Concurrency         int          `json:"concurrency"`
	RequestBudget       int64        `json:"requestBudget"`
	ByteBudget          int64        `json:"byteBudget"`
	TimeWindows         []TimeWindow `json:"timeWindows,omitempty"`
	RetentionDays       int          `json:"retentionDays,omitempty"`
	EmergencyStop       []string     `json:"emergencyStop,omitempty"`
}

func NewScope() Scope {
	return Scope{Versioned: contracts.Versioned{Kind: "scope", Version: contracts.ScopeV1}}
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func (s *Scope) Normalize() error {
	if s.Version != contracts.ScopeV1 {
		return fmt.Errorf("scopeguard: unsupported scope version %q", s.Version)
	}
	s.RootDomains = normalizeList(s.RootDomains, normalizeDomain)
	s.ExactDomains = normalizeList(s.ExactDomains, normalizeDomain)
	s.DeniedAssets = normalizeList(s.DeniedAssets, normalizeDomain)
	s.Protocols = normalizeList(s.Protocols, strings.ToLower)
	for _, d := range append(append([]string{}, s.RootDomains...), s.ExactDomains...) {
		if !domainPattern.MatchString(d) {
			return fmt.Errorf("scopeguard: invalid domain %q", d)
		}
	}
	for _, raw := range s.IPs {
		if _, err := netip.ParseAddr(raw); err != nil {
			return fmt.Errorf("scopeguard: invalid ip %q", raw)
		}
	}
	for _, raw := range s.CIDRs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("scopeguard: invalid cidr %q", raw)
		}
	}
	for _, p := range s.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("scopeguard: invalid port %d", p)
		}
	}
	if s.Concurrency < 0 || s.RequestBudget < 0 || s.ByteBudget < 0 {
		return fmt.Errorf("scopeguard: negative budget values are not allowed")
	}
	return nil
}

func normalizeList(values []string, f func(string) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = f(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (s Scope) Grants(class string) bool {
	for _, c := range s.ScanClasses {
		if c == class {
			return true
		}
	}
	for _, c := range s.VerificationClasses {
		if c == class {
			return true
		}
	}
	return false
}

func (s Scope) DeniesAction(action string) bool {
	for _, a := range s.DeniedActions {
		if a == action {
			return true
		}
	}
	return false
}
