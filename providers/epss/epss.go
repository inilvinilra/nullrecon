package epss

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
	endpoint := "https://api.first.org"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("epss", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapExploitPriority,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "daily"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"cve", "epss", "percentile", "date"}
	d.Terms = "https://www.first.org/epss/"
	d.Redistribution = "public; attribution to FIRST.org"
	d.CacheTTLSeconds = 43200
	return d
}

type dataItem struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

type response struct {
	Status string     `json:"status"`
	Total  int        `json:"total"`
	Data   []dataItem `json:"data"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if q.Capability != registry.CapExploitPriority {
		return registry.RequestSpec{}, fmt.Errorf("epss: capability %s not supported", q.Capability)
	}
	cve := strings.TrimSpace(q.Params["cve"])
	if cve == "" {
		return registry.RequestSpec{}, fmt.Errorf("epss: param cve is required")
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/data/v1/epss",
		Query:  map[string]string{"cve": cve},
	}, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed response
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("epss: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	for _, item := range parsed.Data {
		if item.CVE == "" {
			continue
		}
		page.Records = append(page.Records, registry.Record{
			Kind:           "epss",
			Value:          item.CVE,
			AdapterVersion: adapterVersion,
			Fields: map[string]string{
				"cve":        item.CVE,
				"epss":       item.EPSS,
				"percentile": item.Percentile,
				"date":       item.Date,
			},
		})
	}
	return page, nil
}
