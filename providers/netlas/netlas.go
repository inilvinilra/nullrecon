package netlas

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
	endpoint := "https://app.netlas.io"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("netlas", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapAssetSearch,
		registry.CapServiceSearch,
		registry.CapDomainLookup,
		registry.CapCertificateSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "X-API-Key", SecretRef: "provider/netlas", Required: true}
	d.Pagination = "offset"
	d.FreshnessClass = "daily"
	d.FieldCoverage = []string{"ip", "port", "uri", "host", "protocol"}
	d.Terms = "https://netlas.io/terms"
	d.Redistribution = "verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type searchResponse struct {
	Items []struct {
		Data map[string]any `json:"data"`
	} `json:"items"`
	Total int `json:"total"`
}

var datatypePath = map[registry.Capability]string{
	registry.CapAssetSearch:       "/api/responses/",
	registry.CapServiceSearch:     "/api/responses/",
	registry.CapDomainLookup:      "/api/domains/",
	registry.CapCertificateSearch: "/api/certs/",
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	path, ok := datatypePath[q.Capability]
	if !ok {
		return registry.RequestSpec{}, fmt.Errorf("netlas: capability %s not mapped", q.Capability)
	}
	queryText := q.Params["q"]
	if queryText == "" {
		return registry.RequestSpec{}, fmt.Errorf("netlas: query param q is required")
	}
	start := 0
	if q.Cursor != "" {
		parsed, err := strconv.Atoi(q.Cursor)
		if err != nil || parsed < 0 {
			return registry.RequestSpec{}, fmt.Errorf("netlas: invalid cursor")
		}
		start = parsed
	}
	return registry.RequestSpec{
		Method:  "GET",
		Path:    path,
		Query:   map[string]string{"q": queryText, "start": strconv.Itoa(start)},
		Headers: map[string]string{"X-API-Key": secret},
	}, nil
}

func stringField(data map[string]any, key string) string {
	if v, ok := data[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
	}
	return ""
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed searchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("netlas: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	consumed := 0
	if q.Cursor != "" {
		consumed, _ = strconv.Atoi(q.Cursor)
	}
	consumed += len(parsed.Items)
	if consumed < parsed.Total {
		page.NextCursor = strconv.Itoa(consumed)
	}
	for _, item := range parsed.Items {
		rec := registry.Record{Kind: "service", Fields: map[string]string{}}
		for _, key := range []string{"ip", "port", "uri", "host", "protocol"} {
			if v := stringField(item.Data, key); v != "" {
				rec.Fields[key] = v
			}
		}
		rec.Value = rec.Fields["ip"]
		if rec.Value == "" {
			rec.Value = rec.Fields["uri"]
		}
		if rec.Value == "" {
			rec.Value = rec.Fields["host"]
		}
		page.Records = append(page.Records, rec)
	}
	return page, nil
}
