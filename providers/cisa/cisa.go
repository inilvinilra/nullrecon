package cisa

import (
	"encoding/json"
	"fmt"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://www.cisa.gov"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("cisa-kev", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapExploitPriority,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "daily"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"cve", "vendor", "product", "dateAdded", "dueDate", "ransomware"}
	d.Terms = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
	d.Redistribution = "public domain"
	d.CacheTTLSeconds = 43200
	return d
}

type kevItem struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type catalog struct {
	Title           string    `json:"title"`
	CatalogVersion  string    `json:"catalogVersion"`
	Count           int       `json:"count"`
	Vulnerabilities []kevItem `json:"vulnerabilities"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if q.Capability != registry.CapExploitPriority {
		return registry.RequestSpec{}, fmt.Errorf("cisa: capability %s not supported", q.Capability)
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	}, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed catalog
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("cisa: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	for _, item := range parsed.Vulnerabilities {
		if item.CveID == "" {
			continue
		}
		fields := map[string]string{
			"cve":       item.CveID,
			"vendor":    item.VendorProject,
			"product":   item.Product,
			"dateAdded": item.DateAdded,
			"dueDate":   item.DueDate,
			"kev":       "true",
		}
		if item.KnownRansomwareCampaignUse != "" {
			fields["ransomware"] = item.KnownRansomwareCampaignUse
		}
		page.Records = append(page.Records, registry.Record{
			Kind:           "kev",
			Value:          item.CveID,
			AdapterVersion: adapterVersion,
			Fields:         fields,
		})
	}
	return page, nil
}
