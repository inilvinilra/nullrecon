package virustotal

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
	endpoint := "https://www.virustotal.com"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("virustotal", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapSubdomainSearch,
		registry.CapDomainLookup,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "x-apikey", SecretRef: "provider/virustotal", Required: true}
	d.Pagination = "cursor"
	d.FreshnessClass = "daily"
	d.RatePerSecond = 0.25
	d.FieldCoverage = []string{"hostname"}
	d.Terms = "https://docs.virustotal.com/docs/api-overview"
	d.Redistribution = "restricted; verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type dataItem struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type meta struct {
	Cursor string `json:"cursor"`
	Count  int    `json:"count"`
}

type relationshipResponse struct {
	Data []dataItem `json:"data"`
	Meta meta       `json:"meta"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	domain := strings.TrimSpace(q.Params["domain"])
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("virustotal: param domain is required")
	}
	switch q.Capability {
	case registry.CapSubdomainSearch:
		query := map[string]string{"limit": "40"}
		if q.Cursor != "" {
			query["cursor"] = q.Cursor
		}
		return registry.RequestSpec{
			Method:  "GET",
			Path:    "/api/v3/domains/" + domain + "/subdomains",
			Query:   query,
			Headers: map[string]string{"x-apikey": secret},
		}, nil
	case registry.CapDomainLookup:
		return registry.RequestSpec{
			Method:  "GET",
			Path:    "/api/v3/domains/" + domain,
			Headers: map[string]string{"x-apikey": secret},
		}, nil
	}
	return registry.RequestSpec{}, fmt.Errorf("virustotal: capability %s not supported", q.Capability)
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed relationshipResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("virustotal: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	for _, item := range parsed.Data {
		if item.ID == "" {
			continue
		}
		page.Records = append(page.Records, registry.Record{
			Kind:           "hostname",
			Value:          strings.ToLower(item.ID),
			Fields:         map[string]string{"hostname": strings.ToLower(item.ID)},
			AdapterVersion: adapterVersion,
		})
	}
	if parsed.Meta.Cursor != "" {
		page.NextCursor = parsed.Meta.Cursor
	}
	return page, nil
}
