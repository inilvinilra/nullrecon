package certspotter

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
	endpoint := "https://api.certspotter.com"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("certspotter", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapSubdomainSearch,
		registry.CapCertificateSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "continuous"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"hostname"}
	d.Terms = "https://sslmate.com/certspotter/"
	d.Redistribution = "public certificate transparency data"
	d.CacheTTLSeconds = 3600
	d.TimeoutSeconds = 30
	return d
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	switch q.Capability {
	case registry.CapSubdomainSearch, registry.CapCertificateSearch:
	default:
		return registry.RequestSpec{}, fmt.Errorf("certspotter: capability %s not supported", q.Capability)
	}
	domain := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(q.Params["domain"]), "*."))
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("certspotter: param domain is required")
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/v1/issuances",
		Query: map[string]string{
			"domain":             domain,
			"include_subdomains": "true",
			"expand":             "dns_names",
		},
	}, nil
}

type issuance struct {
	DNSNames []string `json:"dns_names"`
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var entries []issuance
	if err := json.Unmarshal(resp.Body, &entries); err != nil {
		return registry.Page{}, fmt.Errorf("certspotter: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	seen := map[string]bool{}
	for _, entry := range entries {
		for _, raw := range entry.DNSNames {
			name := strings.ToLower(strings.TrimSpace(raw))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || strings.ContainsAny(name, " @") || seen[name] {
				continue
			}
			seen[name] = true
			page.Records = append(page.Records, registry.Record{
				Kind:           "hostname",
				Value:          name,
				Fields:         map[string]string{"hostname": name},
				AdapterVersion: adapterVersion,
			})
		}
	}
	return page, nil
}
