package rapiddns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://rapiddns.io"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("rapiddns", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapSubdomainSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "batch"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"hostname"}
	d.Terms = "https://rapiddns.io"
	d.Redistribution = "public passive DNS scrape; verify current terms"
	d.CacheTTLSeconds = 3600
	d.TimeoutSeconds = 30
	return d
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if q.Capability != registry.CapSubdomainSearch {
		return registry.RequestSpec{}, fmt.Errorf("rapiddns: capability %s not supported", q.Capability)
	}
	domain := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(q.Params["domain"]), "*."))
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("rapiddns: param domain is required")
	}
	return registry.RequestSpec{
		Method:  "GET",
		Path:    "/subdomain/" + domain,
		Query:   map[string]string{"full": "1"},
		Headers: map[string]string{"Accept": "text/html"},
	}, nil
}

var hostCell = regexp.MustCompile(`<td>([A-Za-z0-9_.-]+)</td>`)

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	domain := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(q.Params["domain"]), "*."))
	page := registry.Page{Credits: 1}
	seen := map[string]bool{}
	for _, m := range hostCell.FindAllStringSubmatch(string(resp.Body), -1) {
		name := strings.ToLower(strings.TrimSpace(m[1]))
		name = strings.TrimPrefix(name, "*.")
		name = strings.TrimSuffix(name, ".")
		if name == "" || seen[name] {
			continue
		}
		if domain != "" && name != domain && !strings.HasSuffix(name, "."+domain) {
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
	return page, nil
}
