package crtsh

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://crt.sh"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("crtsh", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapSubdomainSearch,
		registry.CapCertificateSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "continuous"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"hostname", "issuer", "notBefore", "notAfter"}
	d.Terms = "https://crt.sh"
	d.Redistribution = "public certificate transparency data"
	d.CacheTTLSeconds = 3600
	d.TimeoutSeconds = 90
	return d
}

type certEntry struct {
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	switch q.Capability {
	case registry.CapSubdomainSearch, registry.CapCertificateSearch:
	default:
		return registry.RequestSpec{}, fmt.Errorf("crtsh: capability %s not supported", q.Capability)
	}
	domain := strings.TrimSpace(q.Params["domain"])
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("crtsh: param domain is required")
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/",
		Query:  map[string]string{"q": "%." + domain, "output": "json"},
	}, nil
}

func normalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "*.")
	return name
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var entries []certEntry
	if err := json.Unmarshal(resp.Body, &entries); err != nil {
		return registry.Page{}, fmt.Errorf("crtsh: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	seen := map[string]bool{}
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		names = append(names, entry.CommonName)
		for _, raw := range names {
			name := normalizeName(raw)
			if name == "" || strings.ContainsAny(name, " @") || seen[name] {
				continue
			}
			seen[name] = true
			fields := map[string]string{"hostname": name}
			if entry.IssuerName != "" {
				fields["issuer"] = entry.IssuerName
			}
			if entry.NotBefore != "" {
				fields["notBefore"] = entry.NotBefore
			}
			if entry.NotAfter != "" {
				fields["notAfter"] = entry.NotAfter
			}
			page.Records = append(page.Records, registry.Record{
				Kind:           "hostname",
				Value:          name,
				Fields:         fields,
				AdapterVersion: adapterVersion,
			})
		}
	}
	return page, nil
}
