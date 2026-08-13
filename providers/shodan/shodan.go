package shodan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://api.shodan.io"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("shodan", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapHostLookup,
		registry.CapServiceSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthQuery, QueryKey: "key", SecretRef: "provider/shodan", Required: true}
	d.Pagination = "page"
	d.FreshnessClass = "daily"
	d.FieldCoverage = []string{"ip", "ports", "hostnames", "org", "os", "services", "vulns"}
	d.Terms = "https://www.shodan.io/legal/terms-of-service"
	d.Redistribution = "restricted; verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type hostService struct {
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	CPE       []string `json:"cpe"`
	Timestamp string   `json:"timestamp"`
}

type hostResult struct {
	IP        string          `json:"ip_str"`
	Ports     []int           `json:"ports"`
	Hostnames []string        `json:"hostnames"`
	Org       string          `json:"org"`
	OS        string          `json:"os"`
	Data      []hostService   `json:"data"`
	Vulns     json.RawMessage `json:"vulns"`
}

type searchResponse struct {
	Total   int          `json:"total"`
	Matches []hostResult `json:"matches"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	switch q.Capability {
	case registry.CapHostLookup:
		ip := q.Params["ip"]
		if ip == "" {
			return registry.RequestSpec{}, fmt.Errorf("shodan: param ip is required")
		}
		return registry.RequestSpec{
			Method: "GET",
			Path:   "/shodan/host/" + ip,
			Query:  map[string]string{"key": secret},
		}, nil
	case registry.CapServiceSearch:
		queryText := q.Params["q"]
		if queryText == "" {
			return registry.RequestSpec{}, fmt.Errorf("shodan: query param q is required")
		}
		page := 1
		if q.Cursor != "" {
			parsed, err := strconv.Atoi(q.Cursor)
			if err != nil || parsed < 1 {
				return registry.RequestSpec{}, fmt.Errorf("shodan: invalid cursor")
			}
			page = parsed
		}
		return registry.RequestSpec{
			Method: "GET",
			Path:   "/shodan/host/search",
			Query:  map[string]string{"key": secret, "query": queryText, "page": strconv.Itoa(page)},
		}, nil
	}
	return registry.RequestSpec{}, fmt.Errorf("shodan: capability %s not supported", q.Capability)
}

func parseVulns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asMap); err == nil {
		for k := range asMap {
			list = append(list, k)
		}
		return list
	}
	return nil
}

func (a *Adapter) hostToRecords(host hostResult) []registry.Record {
	var out []registry.Record
	observed := time.Time{}
	for _, svc := range host.Data {
		rec := registry.Record{
			Kind:  "service",
			Value: host.IP,
			Fields: map[string]string{
				"ip":        host.IP,
				"port":      strconv.Itoa(svc.Port),
				"transport": svc.Transport,
			},
		}
		if svc.Product != "" {
			rec.Fields["product"] = svc.Product
		}
		if svc.Version != "" {
			rec.Fields["version"] = svc.Version
		}
		if len(svc.CPE) > 0 {
			rec.Fields["cpe"] = strings.Join(svc.CPE, ",")
		}
		if svc.Timestamp != "" {
			if t, err := time.Parse("2006-01-02T15:04:05.999999", svc.Timestamp); err == nil {
				rec.ObservedAt = t.UTC()
				if t.After(observed) {
					observed = t
				}
			}
		}
		out = append(out, rec)
	}
	if vulns := parseVulns(host.Vulns); len(vulns) > 0 {
		rec := registry.Record{
			Kind:       "vulnhint",
			Value:      host.IP,
			Fields:     map[string]string{"ip": host.IP, "vulns": strings.Join(vulns, ",")},
			ObservedAt: observed,
		}
		out = append(out, rec)
	}
	return out
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	page := registry.Page{Credits: 1}
	if q.Capability == registry.CapHostLookup {
		var host hostResult
		if err := json.Unmarshal(resp.Body, &host); err != nil {
			return registry.Page{}, fmt.Errorf("shodan: invalid json: %w", err)
		}
		page.Records = a.hostToRecords(host)
		return page, nil
	}
	var parsed searchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("shodan: invalid json: %w", err)
	}
	currentPage := 1
	if q.Cursor != "" {
		currentPage, _ = strconv.Atoi(q.Cursor)
	}
	if currentPage*100 < parsed.Total {
		page.NextCursor = strconv.Itoa(currentPage + 1)
	}
	for _, match := range parsed.Matches {
		page.Records = append(page.Records, a.hostToRecords(match)...)
	}
	return page, nil
}
