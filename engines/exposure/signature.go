package exposure

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed signatures.json
var signatureData []byte

const SignaturesVersion = "nr.rules/v1"

type Signature struct {
	ID             string   `json:"id"`
	Path           string   `json:"path"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	MustContain    []string `json:"mustContain,omitempty"`
	MustContainAny []string `json:"mustContainAny,omitempty"`
	MustNotContain []string `json:"mustNotContain,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
}

type compiledSignature struct {
	Signature
	pattern *regexp.Regexp
}

type SignatureSet struct {
	signatures []compiledSignature
}

type signatureDoc struct {
	Version    string      `json:"version"`
	Kind       string      `json:"kind"`
	Signatures []Signature `json:"signatures"`
}

func LoadSignatures() (*SignatureSet, error) {
	var doc signatureDoc
	if err := json.Unmarshal(signatureData, &doc); err != nil {
		return nil, fmt.Errorf("exposure: invalid signatures: %w", err)
	}
	if doc.Version != SignaturesVersion {
		return nil, fmt.Errorf("exposure: unsupported signatures version %q", doc.Version)
	}
	return NewSignatureSet(doc.Signatures)
}

func NewSignatureSet(signatures []Signature) (*SignatureSet, error) {
	set := &SignatureSet{}
	seen := map[string]bool{}
	for _, sig := range signatures {
		if sig.ID == "" {
			return nil, fmt.Errorf("exposure: signature with empty id")
		}
		if seen[sig.ID] {
			return nil, fmt.Errorf("exposure: duplicate signature id %q", sig.ID)
		}
		seen[sig.ID] = true
		compiled := compiledSignature{Signature: sig}
		if sig.Pattern != "" {
			re, err := regexp.Compile(sig.Pattern)
			if err != nil {
				return nil, fmt.Errorf("exposure: signature %q has invalid pattern: %w", sig.ID, err)
			}
			compiled.pattern = re
		}
		set.signatures = append(set.signatures, compiled)
	}
	if len(set.signatures) == 0 {
		return nil, fmt.Errorf("exposure: no signatures loaded")
	}
	return set, nil
}

func (s *SignatureSet) Len() int {
	return len(s.signatures)
}

func (c compiledSignature) matches(body []byte) ([]string, bool) {
	lower := strings.ToLower(string(body))
	var reasons []string
	for _, needle := range c.MustNotContain {
		if strings.Contains(lower, strings.ToLower(needle)) {
			return nil, false
		}
	}
	for _, needle := range c.MustContain {
		if !strings.Contains(lower, strings.ToLower(needle)) {
			return nil, false
		}
		reasons = append(reasons, "contains:"+needle)
	}
	if len(c.MustContainAny) > 0 {
		matchedAny := false
		for _, needle := range c.MustContainAny {
			if strings.Contains(lower, strings.ToLower(needle)) {
				reasons = append(reasons, "contains:"+needle)
				matchedAny = true
				break
			}
		}
		if !matchedAny {
			return nil, false
		}
	}
	if c.pattern != nil {
		if !c.pattern.Match(body) {
			return nil, false
		}
		reasons = append(reasons, "pattern")
	}
	if len(reasons) == 0 {
		return nil, false
	}
	return reasons, true
}
