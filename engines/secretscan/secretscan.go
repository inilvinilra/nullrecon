package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type Candidate struct {
	DetectorID  string  `json:"detectorId"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Fingerprint string  `json:"fingerprint"`
	Preview     string  `json:"preview"`
	Entropy     float64 `json:"entropy"`
	Location    string  `json:"location"`
	Line        int     `json:"line"`
	State       string  `json:"state"`
}

type Result struct {
	Location   string      `json:"location"`
	Candidates []Candidate `json:"candidates"`
	Suppressed int         `json:"suppressed"`
}

func Scan(set *DetectorSet, content []byte, location string) Result {
	text := string(content)
	res := Result{Location: location}
	seen := map[string]bool{}
	for _, det := range set.detectors {
		matches := det.re.FindAllStringSubmatchIndex(text, -1)
		for _, idx := range matches {
			secret := extractGroup(text, idx, det.Group)
			if secret == "" {
				continue
			}
			state := classify(det, secret)
			fingerprint := fingerprintOf(secret)
			dedupeKey := det.ID + ":" + fingerprint
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			if state != "confirmed" {
				res.Suppressed++
				continue
			}
			res.Candidates = append(res.Candidates, Candidate{
				DetectorID:  det.ID,
				Category:    det.Category,
				Severity:    det.Severity,
				Fingerprint: fingerprint,
				Preview:     preview(secret),
				Entropy:     round2(shannonEntropy(secret)),
				Location:    location,
				Line:        lineOf(text, idx[0]),
				State:       state,
			})
		}
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Line != res.Candidates[j].Line {
			return res.Candidates[i].Line < res.Candidates[j].Line
		}
		return res.Candidates[i].DetectorID < res.Candidates[j].DetectorID
	})
	return res
}

func classify(det Detector, secret string) string {
	if isPlaceholder(secret) {
		return "placeholder"
	}
	if det.MinEntropy > 0 && shannonEntropy(secret) < det.MinEntropy {
		return "lowentropy"
	}
	return "confirmed"
}

func extractGroup(text string, idx []int, group int) string {
	pos := group * 2
	if pos+1 >= len(idx) || idx[pos] < 0 || idx[pos+1] < 0 {
		if len(idx) >= 2 && idx[0] >= 0 {
			return text[idx[0]:idx[1]]
		}
		return ""
	}
	return text[idx[pos]:idx[pos+1]]
}

func fingerprintOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func preview(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) <= 4 {
		return "****"
	}
	head := trimmed[:3]
	return head + "***(len=" + itoa(len(trimmed)) + ")"
}

func lineOf(text string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
