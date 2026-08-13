package censys

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://search.censys.io"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("censys", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapHostLookup,
		registry.CapServiceSearch,
		registry.CapCertificateSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "Authorization", SecretRef: "provider/censys", Required: true}
	d.Pagination = "cursor"
	d.FreshnessClass = "daily"
	d.FieldCoverage = []string{"ip", "services.port", "services.service_name", "autonomous_system", "location"}
	d.Terms = "https://censys.com/terms"
	d.Redistribution = "verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type searchResult struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result struct {
		Total int `json:"total"`
		Hits  []struct {
			IP       string `json:"ip"`
			Name     string `json:"name"`
			Services []struct {
				Port        uint16 `json:"port"`
				ServiceName string `json:"service_name"`
				Transport   string `json:"transport_protocol"`
			} `json:"services"`
			ASN struct {
				ASN         int    `json:"asn"`
				Description string `json:"description"`
			} `json:"autonomous_system"`
			LastUpdated string `json:"last_updated_at"`
		} `json:"hits"`
		Links struct {
			Next string `json:"next"`
			Prev string `json:"prev"`
		} `json:"links"`
	} `json:"result"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	queryText := q.Params["q"]
	if queryText == "" {
		return registry.RequestSpec{}, fmt.Errorf("censys: query param q is required")
	}
	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := map[string]string{"q": queryText, "per_page": strconv.Itoa(limit)}
	if q.Cursor != "" {
		query["cursor"] = q.Cursor
	}
	return registry.RequestSpec{
		Method:  "GET",
		Path:    "/api/v2/hosts/search",
		Query:   query,
		Headers: map[string]string{"Authorization": "Bearer " + secret},
	}, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed searchResult
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("censys: invalid json: %w", err)
	}
	if resp.Status != 200 {
		return registry.Page{}, fmt.Errorf("censys: api status %d: %s", resp.Status, parsed.Status)
	}
	page := registry.Page{NextCursor: parsed.Result.Links.Next, Credits: 1}
	for _, hit := range parsed.Result.Hits {
		rec := registry.Record{
			Kind:  "host",
			Value: hit.IP,
			Fields: map[string]string{
				"ip": hit.IP,
			},
		}
		if hit.Name != "" {
			rec.Fields["name"] = hit.Name
		}
		if hit.ASN.ASN != 0 {
			rec.Fields["asn"] = strconv.Itoa(hit.ASN.ASN)
			rec.Fields["asnDescription"] = hit.ASN.Description
		}
		if len(hit.Services) > 0 {
			ports := ""
			for i, s := range hit.Services {
				if i > 0 {
					ports += ","
				}
				ports += strconv.Itoa(int(s.Port)) + "/" + s.ServiceName
			}
			rec.Fields["services"] = ports
		}
		page.Records = append(page.Records, rec)
	}
	return page, nil
}
