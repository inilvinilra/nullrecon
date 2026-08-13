package dnsbrute

import (
	_ "embed"
	"strings"
)

//go:embed words.txt
var embeddedWords string

func DefaultWords() []string {
	var out []string
	for _, line := range strings.Split(embeddedWords, "\n") {
		w := strings.TrimSpace(line)
		if w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out
}
