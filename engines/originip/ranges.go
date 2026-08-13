package originip

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
)

//go:embed cdnranges.json
var rangesData []byte

const RangesVersion = "nr.rules/v1"

type providerDoc struct {
	Version   string           `json:"version"`
	Kind      string           `json:"kind"`
	Providers []providerRecord `json:"providers"`
}

type providerRecord struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Category string   `json:"category"`
	V4       []string `json:"v4"`
	V6       []string `json:"v6"`
}

type netEntry struct {
	prefix   netip.Prefix
	provider string
}

type providerInfo struct {
	Label    string
	Category string
}

type NetworkMap struct {
	entries []netEntry
	byName  map[string]providerInfo
}

func LoadNetworkMap() (*NetworkMap, error) {
	var doc providerDoc
	if err := json.Unmarshal(rangesData, &doc); err != nil {
		return nil, fmt.Errorf("originip: invalid ranges data: %w", err)
	}
	if doc.Version != RangesVersion {
		return nil, fmt.Errorf("originip: unsupported ranges version %q", doc.Version)
	}
	nm := &NetworkMap{byName: map[string]providerInfo{}}
	for _, p := range doc.Providers {
		nm.byName[p.Name] = providerInfo{Label: p.Label, Category: p.Category}
		for _, cidr := range append(append([]string{}, p.V4...), p.V6...) {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			nm.entries = append(nm.entries, netEntry{prefix: prefix.Masked(), provider: p.Name})
		}
	}
	if len(nm.entries) == 0 {
		return nil, fmt.Errorf("originip: ranges data contained no valid networks")
	}
	return nm, nil
}

func (nm *NetworkMap) Classify(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	for _, e := range nm.entries {
		if e.prefix.Contains(addr) {
			return e.provider, true
		}
	}
	return "", false
}

func (nm *NetworkMap) Label(provider string) string {
	return nm.byName[provider].Label
}

func (nm *NetworkMap) Category(provider string) string {
	return nm.byName[provider].Category
}

func (nm *NetworkMap) Providers() int {
	return len(nm.byName)
}

func (nm *NetworkMap) Ranges() int {
	return len(nm.entries)
}
