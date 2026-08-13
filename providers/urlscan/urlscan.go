package urlscan

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
	endpoint := "https://urlscan.io"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("urlscan", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapURLHistory,
		registry.CapSubdomainSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "API-Key", SecretRef: "provider/urlscan", Required: false}
	d.Pagination = "cursor"
	d.FreshnessClass = "continuous"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"url", "domain", "ip", "server", "asn"}
	d.Terms = "https://urlscan.io/about-api/"
	d.Redistribution = "restricted; verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type task struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	Time   string `json:"time"`
}

type pageInfo struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Server string `json:"server"`
	ASN    string `json:"asn"`
}

type result struct {
	ID   string   `json:"_id"`
	Task task     `json:"task"`
	Page pageInfo `json:"page"`
	Sort []any    `json:"sort"`
}

type searchResponse struct {
	Results []result `json:"results"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	switch q.Capability {
	case registry.CapURLHistory, registry.CapSubdomainSearch:
	default:
		return registry.RequestSpec{}, fmt.Errorf("urlscan: capability %s not supported", q.Capability)
	}
	domain := strings.TrimSpace(q.Params["domain"])
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("urlscan: param domain is required")
	}
	query := map[string]string{"q": "domain:" + domain}
	if q.Cursor != "" {
		query["search_after"] = q.Cursor
	}
	spec := registry.RequestSpec{Method: "GET", Path: "/api/v1/search/", Query: query}
	if secret != "" {
		spec.Headers = map[string]string{"API-Key": secret}
	}
	return spec, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed searchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("urlscan: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	seen := map[string]bool{}
	for _, r := range parsed.Results {
		if r.Page.Domain != "" && !seen["h:"+r.Page.Domain] {
			seen["h:"+r.Page.Domain] = true
			fields := map[string]string{"hostname": r.Page.Domain}
			if r.Page.IP != "" {
				fields["ip"] = r.Page.IP
			}
			if r.Page.Server != "" {
				fields["server"] = r.Page.Server
			}
			if r.Page.ASN != "" {
				fields["asn"] = r.Page.ASN
			}
			page.Records = append(page.Records, registry.Record{Kind: "hostname", Value: r.Page.Domain, Fields: fields, AdapterVersion: adapterVersion})
		}
		if r.Task.URL != "" && !seen["u:"+r.Task.URL] {
			seen["u:"+r.Task.URL] = true
			page.Records = append(page.Records, registry.Record{
				Kind:           "url",
				Value:          r.Task.URL,
				Fields:         map[string]string{"url": r.Task.URL, "domain": r.Task.Domain},
				AdapterVersion: adapterVersion,
			})
		}
	}
	if parsed.HasMore && len(parsed.Results) > 0 {
		last := parsed.Results[len(parsed.Results)-1]
		if len(last.Sort) > 0 {
			parts := make([]string, 0, len(last.Sort))
			for _, s := range last.Sort {
				parts = append(parts, fmt.Sprintf("%v", s))
			}
			page.NextCursor = strings.Join(parts, ",")
		}
	}
	return page, nil
}
