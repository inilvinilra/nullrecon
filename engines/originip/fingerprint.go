package originip

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
)

type Reference struct {
	Status      int    `json:"status"`
	Title       string `json:"title,omitempty"`
	BodyHash    string `json:"bodyHash,omitempty"`
	FaviconMMH3 *int32 `json:"faviconMmh3,omitempty"`
	Error       string `json:"error,omitempty"`
}

type probeResult struct {
	Status      int
	Title       string
	BodyHash    string
	FaviconMMH3 *int32
}

const (
	weightStatus  = 0.1
	weightTitle   = 0.5
	weightPartial = 0.2
	weightBody    = 0.2
	weightFavicon = 0.4
)

func compare(candidate probeResult, ref Reference) (float64, []string) {
	score := 0.0
	var reasons []string
	if candidate.Status != 0 && ref.Status != 0 && candidate.Status == ref.Status {
		score += weightStatus
	}
	if candidate.Title != "" && ref.Title != "" {
		switch {
		case candidate.Title == ref.Title:
			score += weightTitle
			reasons = append(reasons, "title")
		case strings.Contains(candidate.Title, ref.Title) || strings.Contains(ref.Title, candidate.Title):
			score += weightPartial
			reasons = append(reasons, "title_partial")
		}
	}
	if candidate.BodyHash != "" && ref.BodyHash != "" && candidate.BodyHash == ref.BodyHash {
		score += weightBody
		reasons = append(reasons, "body")
	}
	if candidate.FaviconMMH3 != nil && ref.FaviconMMH3 != nil && *candidate.FaviconMMH3 == *ref.FaviconMMH3 {
		score += weightFavicon
		reasons = append(reasons, "favicon")
	}
	return score, reasons
}

func matchState(score float64, reasons []string) string {
	strong := false
	hasTitle := false
	for _, r := range reasons {
		switch r {
		case "body", "favicon":
			strong = true
		case "title":
			hasTitle = true
		}
	}
	switch {
	case strong && score >= 0.5:
		return "confirmed"
	case hasTitle && score >= 0.5:
		return "likely"
	case score > 0 && len(reasons) > 0:
		return "potential"
	default:
		return "rejected"
	}
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := titlePattern.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(string(m[1]))
	if len(title) > 256 {
		title = title[:256]
	}
	return title
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func isPublicIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return false
	}
	return true
}
