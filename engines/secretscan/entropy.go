package secretscan

import (
	"math"
	"strings"
)

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	for _, c := range counts {
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var placeholderMarkers = []string{
	"example", "sample", "your_", "your-", "yourkey", "changeme", "change_me",
	"placeholder", "dummy", "redacted", "xxxxxx", "000000", "123456",
	"insert", "replace", "test_key", "testkey", "fake", "notreal", "somekey",
	"aaaaaa", "abcdef", "deadbeef", "<", "{{", "%s", "...",
}

var exampleSecrets = map[string]bool{
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,
	"AKIAIOSFODNN7EXAMPLF":                     true,
}

func isPlaceholder(secret string) bool {
	if exampleSecrets[secret] {
		return true
	}
	lower := strings.ToLower(secret)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if isRepeatedRun(secret) {
		return true
	}
	return false
}

func isRepeatedRun(secret string) bool {
	if len(secret) < 6 {
		return false
	}
	first := secret[0]
	same := true
	for i := 1; i < len(secret); i++ {
		if secret[i] != first {
			same = false
			break
		}
	}
	return same
}
