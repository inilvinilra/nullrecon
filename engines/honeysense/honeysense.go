package honeysense

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

type Signals struct {
	OpenPorts            []int          `json:"openPorts,omitempty"`
	Banners              map[int]string `json:"banners,omitempty"`
	TLSSubjects          map[int]string `json:"tlsSubjects,omitempty"`
	ResponseTimesMS      []int64        `json:"responseTimesMs,omitempty"`
	OSTraitInconsistent  bool           `json:"osTraitInconsistent,omitempty"`
	ProviderDisagreement bool           `json:"providerDisagreement,omitempty"`
	ConnectionAnomalies  int            `json:"connectionAnomalies,omitempty"`
	SyntheticErrors      int            `json:"syntheticErrors,omitempty"`
	KnownHoneypotBanner  bool           `json:"knownHoneypotBanner,omitempty"`
	ObservedAt           time.Time      `json:"observedAt"`
}

type Component struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

type Verdict struct {
	Score          float64     `json:"score"`
	Components     []Component `json:"components"`
	Recommendation string      `json:"recommendation"`
	RequiresReview bool        `json:"requiresReview"`
}

func Score(s Signals) Verdict {
	var components []Component
	add := func(name string, score, weight float64, detail string) {
		if score > 1 {
			score = 1
		}
		if score < 0 {
			score = 0
		}
		components = append(components, Component{Name: name, Score: score, Weight: weight, Detail: detail})
	}

	density := portDensity(s.OpenPorts)
	add("port-density", density, 0.35, portDensityDetail(len(s.OpenPorts)))
	add("banner-repetition", bannerRepetition(s.Banners), 0.40, "repeated banners across unrelated ports")
	add("protocol-contradiction", bannerContradiction(s.OpenPorts, s.Banners), 0.30, "banner does not match port protocol")
	add("tls-identity", tlsContradiction(s.TLSSubjects), 0.20, "tls identities contradict across ports")
	add("timing-uniformity", timingUniformity(s.ResponseTimesMS), 0.15, "response timing is implausibly uniform")
	if s.KnownHoneypotBanner {
		add("known-honeypot-fingerprint", 1, 0.55, "banner matches known honeypot fingerprint")
	} else {
		add("known-honeypot-fingerprint", 0, 0.55, "no known honeypot fingerprint")
	}
	if s.SyntheticErrors > 0 {
		add("synthetic-errors", float64(s.SyntheticErrors)/3.0, 0.15, "synthetic error patterns observed")
	} else {
		add("synthetic-errors", 0, 0.15, "no synthetic error patterns")
	}
	if s.OSTraitInconsistent {
		add("os-traits", 0.8, 0.10, "inconsistent operating system traits")
	} else {
		add("os-traits", 0, 0.10, "consistent operating system traits")
	}
	if s.ProviderDisagreement {
		add("provider-disagreement", 0.7, 0.10, "providers disagree about this host")
	} else {
		add("provider-disagreement", 0, 0.10, "providers agree")
	}
	if s.ConnectionAnomalies > 0 {
		add("connection-behavior", float64(s.ConnectionAnomalies)/3.0, 0.10, "connection behavior anomalies")
	} else {
		add("connection-behavior", 0, 0.10, "normal connection behavior")
	}

	totalWeight := 0.0
	total := 0.0
	for _, c := range components {
		total += c.Score * c.Weight
		totalWeight += c.Weight
	}
	_ = totalWeight
	score := total
	if score > 1 {
		score = 1
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Score*components[i].Weight > components[j].Score*components[j].Weight
	})
	v := Verdict{Score: score, Components: components}
	switch {
	case score >= 0.65:
		v.Recommendation = "reduce-intensity"
		v.RequiresReview = true
	case score >= 0.4:
		v.Recommendation = "reduce-intensity"
	default:
		v.Recommendation = "normal"
	}
	return v
}

func portDensity(ports []int) float64 {
	n := len(ports)
	switch {
	case n >= 50:
		return 1
	case n >= 20:
		return 0.8
	case n >= 10:
		return 0.5
	case n >= 6:
		return 0.25
	default:
		return 0
	}
}

func portDensityDetail(n int) string {
	return "open port count " + strconv.Itoa(n)
}

func bannerRepetition(banners map[int]string) float64 {
	counts := map[string]int{}
	for _, b := range banners {
		if b != "" {
			counts[b]++
		}
	}
	max := 0
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	if max >= 5 {
		return 1
	}
	if max >= 3 {
		return 0.7
	}
	if max >= 2 {
		return 0.4
	}
	return 0
}

var expectedProtocol = map[int][]string{
	22:   {"ssh"},
	25:   {"smtp"},
	53:   {"dns"},
	80:   {"http"},
	110:  {"pop3"},
	143:  {"imap"},
	443:  {"http", "tls"},
	3306: {"mysql"},
	3389: {"rdp", "ms-term"},
	5432: {"postgres"},
	6379: {"redis"},
}

func bannerContradiction(ports []int, banners map[int]string) float64 {
	contradictions := 0
	checked := 0
	for _, port := range ports {
		banner := banners[port]
		if banner == "" {
			continue
		}
		expected, ok := expectedProtocol[port]
		if !ok {
			continue
		}
		checked++
		match := false
		lower := strings.ToLower(banner)
		for _, want := range expected {
			if strings.Contains(lower, want) {
				match = true
				break
			}
		}
		if !match {
			contradictions++
		}
	}
	if checked == 0 {
		return 0
	}
	return float64(contradictions) / float64(checked)
}

func tlsContradiction(subjects map[int]string) float64 {
	seen := map[string]int{}
	for _, s := range subjects {
		if s != "" {
			seen[s]++
		}
	}
	if len(seen) > 3 {
		return 0.8
	}
	if len(seen) > 1 {
		return 0.4
	}
	return 0
}

func timingUniformity(times []int64) float64 {
	if len(times) < 4 {
		return 0
	}
	var min, max int64 = times[0], times[0]
	var sum int64
	for _, t := range times {
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
		sum += t
	}
	mean := sum / int64(len(times))
	if mean == 0 {
		return 0
	}
	spread := float64(max-min) / float64(mean)
	if spread < 0.02 {
		return 0.9
	}
	if spread < 0.1 {
		return 0.5
	}
	return 0
}
