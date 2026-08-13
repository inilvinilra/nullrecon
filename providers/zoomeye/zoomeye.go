package zoomeye

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://api.zoomeye.org"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("zoomeye", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapServiceSearch,
		registry.CapHostLookup,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "API-KEY", SecretRef: "provider/zoomeye", Required: true}
	d.Pagination = "page"
	d.FreshnessClass = "daily"
	d.RatePerSecond = 0.5
	d.FieldCoverage = []string{"ip", "port", "service", "product", "version"}
	d.Terms = "https://www.zoomeye.org/doc"
	d.Redistribution = "restricted; verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type portInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	App     string `json:"app"`
	Version string `json:"version"`
	Banner  string `json:"banner"`
}

type match struct {
	IP       string   `json:"ip"`
	PortInfo portInfo `json:"portinfo"`
}

type searchResponse struct {
	Matches   []match `json:"matches"`
	Total     int     `json:"total"`
	Available int     `json:"available"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	switch q.Capability {
	case registry.CapServiceSearch:
		queryText := strings.TrimSpace(q.Params["q"])
		if queryText == "" {
			return registry.RequestSpec{}, fmt.Errorf("zoomeye: param q is required")
		}
		page := 1
		if q.Cursor != "" {
			parsed, err := strconv.Atoi(q.Cursor)
			if err != nil || parsed < 1 {
				return registry.RequestSpec{}, fmt.Errorf("zoomeye: invalid cursor")
			}
			page = parsed
		}
		return registry.RequestSpec{
			Method:  "GET",
			Path:    "/host/search",
			Query:   map[string]string{"query": queryText, "page": strconv.Itoa(page)},
			Headers: map[string]string{"API-KEY": secret},
		}, nil
	case registry.CapHostLookup:
		ip := strings.TrimSpace(q.Params["ip"])
		if ip == "" {
			return registry.RequestSpec{}, fmt.Errorf("zoomeye: param ip is required")
		}
		return registry.RequestSpec{
			Method:  "GET",
			Path:    "/host/search",
			Query:   map[string]string{"query": "ip:" + ip, "page": "1"},
			Headers: map[string]string{"API-KEY": secret},
		}, nil
	}
	return registry.RequestSpec{}, fmt.Errorf("zoomeye: capability %s not supported", q.Capability)
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed searchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("zoomeye: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	for _, m := range parsed.Matches {
		if m.IP == "" {
			continue
		}
		fields := map[string]string{"ip": m.IP}
		if m.PortInfo.Port > 0 {
			fields["port"] = strconv.Itoa(m.PortInfo.Port)
		}
		if m.PortInfo.Service != "" {
			fields["service"] = m.PortInfo.Service
		}
		if m.PortInfo.App != "" {
			fields["product"] = m.PortInfo.App
		}
		if m.PortInfo.Version != "" {
			fields["version"] = m.PortInfo.Version
		}
		page.Records = append(page.Records, registry.Record{Kind: "service", Value: m.IP, Fields: fields, AdapterVersion: adapterVersion})
	}
	currentPage := 1
	if q.Cursor != "" {
		currentPage, _ = strconv.Atoi(q.Cursor)
	}
	if currentPage*20 < parsed.Total {
		page.NextCursor = strconv.Itoa(currentPage + 1)
	}
	return page, nil
}
