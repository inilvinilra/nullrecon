package main

import (
	"context"
	"sort"

	"github.com/nullrecon/nullrecon/providers/registry"
)

type serviceEntry struct {
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Capabilities []string `json:"capabilities"`
	AuthRequired bool     `json:"authRequired"`
	FreeNoKey    bool     `json:"freeNoKey"`
	Configured   bool     `json:"configured"`
	Endpoint     string   `json:"endpoint"`
	Terms        string   `json:"terms,omitempty"`
}

func (c commandContext) cmdService(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return c.fail(exitUsage, "service requires the list subcommand")
	}
	reg := buildRegistry()
	configured := map[string]bool{}
	if db, err := c.openDB(); err == nil {
		defer db.Close()
		for _, d := range reg.Descriptors() {
			if _, err := db.ProviderConfigs().Get(context.Background(), d.Name); err == nil {
				configured[d.Name] = true
			}
		}
	}
	categoryFilter, hasFilter := flagValue(args, "--category")
	var entries []serviceEntry
	byCategory := map[string]int{}
	for _, d := range reg.Descriptors() {
		category := categoryForCapabilities(d.Capabilities)
		if hasFilter && category != categoryFilter {
			continue
		}
		caps := make([]string, 0, len(d.Capabilities))
		for _, cap := range d.Capabilities {
			caps = append(caps, string(cap))
		}
		sort.Strings(caps)
		entries = append(entries, serviceEntry{
			Name:         d.Name,
			Category:     category,
			Capabilities: caps,
			AuthRequired: d.Auth.Required,
			FreeNoKey:    d.Auth.Kind == registry.AuthNone,
			Configured:   configured[d.Name],
			Endpoint:     d.Endpoint,
			Terms:        d.Terms,
		})
		byCategory[category]++
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Category != entries[j].Category {
			return entries[i].Category < entries[j].Category
		}
		return entries[i].Name < entries[j].Name
	})
	return c.emit(map[string]any{"services": entries, "count": len(entries), "byCategory": byCategory})
}

func categoryForCapabilities(caps []registry.Capability) string {
	has := func(want registry.Capability) bool {
		for _, c := range caps {
			if c == want {
				return true
			}
		}
		return false
	}
	switch {
	case has(registry.CapCVELookup) || has(registry.CapCPELookup) || has(registry.CapAdvisoryLookup) || has(registry.CapExploitPriority):
		return "vulnerability-intel"
	case has(registry.CapLeakSearch) || has(registry.CapSecretSignalSearch) || has(registry.CapBreachDomainLookup) || has(registry.CapRepoSearch):
		return "leak-intel"
	case has(registry.CapURLHistory) || has(registry.CapURLSubmit):
		return "url-intel"
	case has(registry.CapNoiseLookup):
		return "reputation"
	case has(registry.CapAssetSearch) || has(registry.CapHostLookup) || has(registry.CapServiceSearch) || has(registry.CapCertificateSearch) || has(registry.CapSubdomainSearch) || has(registry.CapDNSCurrent) || has(registry.CapDNSHistory) || has(registry.CapDomainLookup):
		return "attack-surface"
	}
	return "other"
}
