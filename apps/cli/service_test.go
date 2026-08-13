package main

import (
	"testing"

	"github.com/nullrecon/nullrecon/providers/registry"
)

func TestCategoryForCapabilities(t *testing.T) {
	cases := []struct {
		caps []registry.Capability
		want string
	}{
		{[]registry.Capability{registry.CapCVELookup}, "vulnerability-intel"},
		{[]registry.Capability{registry.CapExploitPriority}, "vulnerability-intel"},
		{[]registry.Capability{registry.CapHostLookup, registry.CapServiceSearch}, "attack-surface"},
		{[]registry.Capability{registry.CapLeakSearch}, "leak-intel"},
		{[]registry.Capability{registry.CapURLHistory}, "url-intel"},
		{[]registry.Capability{registry.CapNoiseLookup}, "reputation"},
	}
	for _, tc := range cases {
		if got := categoryForCapabilities(tc.caps); got != tc.want {
			t.Fatalf("categoryForCapabilities(%v)=%q want %q", tc.caps, got, tc.want)
		}
	}
}

func TestServiceListRegistersCVEFeeds(t *testing.T) {
	reg := buildRegistry()
	want := map[string]bool{"nvd": false, "epss": false, "cisa-kev": false}
	for _, d := range reg.Descriptors() {
		if _, ok := want[d.Name]; ok {
			want[d.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("CVE feed provider %q must be registered", name)
		}
	}
}
