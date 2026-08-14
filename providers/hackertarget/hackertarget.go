package hackertarget

import (
	"fmt"
	"strings"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://api.hackertarget.com"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("hackertarget", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapSubdomainSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthNone, Required: false}
	d.FreshnessClass = "continuous"
	d.RatePerSecond = 1
	d.FieldCoverage = []string{"hostname", "address"}
	d.Terms = "https://hackertarget.com/ip-tools/"
	d.Redistribution = "public host search; free tier is rate limited"
	d.CacheTTLSeconds = 3600
	d.TimeoutSeconds = 30
	return d
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if q.Capability != registry.CapSubdomainSearch {
		return registry.RequestSpec{}, fmt.Errorf("hackertarget: capability %s not supported", q.Capability)
	}
	domain := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(q.Params["domain"]), "*."))
	if domain == "" {
		return registry.RequestSpec{}, fmt.Errorf("hackertarget: param domain is required")
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/hostsearch/",
		Query:  map[string]string{"q": domain},
	}, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	text := strings.TrimSpace(string(resp.Body))
	if text == "" {
		return registry.Page{Credits: 1}, nil
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "api count exceeded") || strings.Contains(lower, "error check") || strings.HasPrefix(lower, "error") {
		return registry.Page{}, fmt.Errorf("hackertarget: %s", firstLine(text))
	}
	page := registry.Page{Credits: 1}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host, address, _ := strings.Cut(line, ",")
		host = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(host, "*.")))
		if host == "" || strings.ContainsAny(host, " @") || seen[host] {
			continue
		}
		seen[host] = true
		fields := map[string]string{"hostname": host}
		if a := strings.TrimSpace(address); a != "" {
			fields["address"] = a
		}
		page.Records = append(page.Records, registry.Record{
			Kind:           "hostname",
			Value:          host,
			Fields:         fields,
			AdapterVersion: adapterVersion,
		})
	}
	return page, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
