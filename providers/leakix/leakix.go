package leakix

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://leakix.net"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("leakix", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapLeakSearch,
		registry.CapHostLookup,
		registry.CapSubdomainSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "api-key", SecretRef: "provider/leakix", Required: true}
	d.Pagination = "single-page"
	d.FreshnessClass = "hourly"
	d.FieldCoverage = []string{"ip", "port", "type", "plugin", "time", "network.asn"}
	d.Terms = "https://leakix.net/terms"
	d.Redistribution = "metadata only; never redistribute leak contents"
	d.CacheTTLSeconds = 1800
	return d
}

type event struct {
	IP       string `json:"ip"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	Time     string `json:"time"`
	Plugin   string `json:"plugin"`
	Network  struct {
		ASN     int    `json:"asn"`
		OrgName string `json:"organization_name"`
	} `json:"network"`
	Dataset struct {
		Rows      int64 `json:"rows"`
		Size      int64 `json:"size"`
		Databases int   `json:"databases"`
		Infected  bool  `json:"infected"`
	} `json:"dataset"`
}

type hostResponse struct {
	Services []event `json:"Services"`
	Leaks    []event `json:"Leaks"`
}

type subdomain struct {
	Subdomain   string `json:"subdomain"`
	DistinctIPs int    `json:"distinct_ips"`
	LastSeen    string `json:"last_seen"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	headers := map[string]string{"api-key": secret, "Accept": "application/json"}
	switch q.Capability {
	case registry.CapLeakSearch:
		queryText := q.Params["q"]
		if queryText == "" {
			return registry.RequestSpec{}, fmt.Errorf("leakix: query param q is required")
		}
		scope := q.Params["scope"]
		if scope != "service" {
			scope = "leak"
		}
		return registry.RequestSpec{Method: "GET", Path: "/search", Query: map[string]string{"q": queryText, "scope": scope}, Headers: headers}, nil
	case registry.CapHostLookup:
		ip := q.Params["ip"]
		if ip == "" {
			return registry.RequestSpec{}, fmt.Errorf("leakix: param ip is required")
		}
		return registry.RequestSpec{Method: "GET", Path: "/host/" + ip, Headers: headers}, nil
	case registry.CapSubdomainSearch:
		domain := q.Params["domain"]
		if domain == "" {
			return registry.RequestSpec{}, fmt.Errorf("leakix: param domain is required")
		}
		return registry.RequestSpec{Method: "GET", Path: "/subdomains/" + domain, Headers: headers}, nil
	}
	return registry.RequestSpec{}, fmt.Errorf("leakix: capability %s not supported", q.Capability)
}

func eventToRecord(e event, kind string) registry.Record {
	rec := registry.Record{
		Kind:   kind,
		Value:  e.IP,
		Fields: map[string]string{},
	}
	if rec.Value == "" {
		rec.Value = e.Host
	}
	put := func(k, v string) {
		if v != "" {
			rec.Fields[k] = v
		}
	}
	put("ip", e.IP)
	put("host", e.Host)
	put("port", e.Port)
	put("protocol", e.Protocol)
	put("type", e.Type)
	put("plugin", e.Plugin)
	if e.Network.ASN != 0 {
		rec.Fields["asn"] = strconv.Itoa(e.Network.ASN)
	}
	put("asnOrg", e.Network.OrgName)
	if kind == "leak" {
		if e.Dataset.Rows != 0 {
			rec.Fields["datasetRows"] = strconv.FormatInt(e.Dataset.Rows, 10)
		}
		if e.Dataset.Infected {
			rec.Fields["datasetInfected"] = "true"
		}
	}
	if e.Time != "" {
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			rec.ObservedAt = t.UTC()
		}
	}
	return rec
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	page := registry.Page{Credits: 1}
	switch q.Capability {
	case registry.CapLeakSearch:
		var events []event
		if err := json.Unmarshal(resp.Body, &events); err != nil {
			return registry.Page{}, fmt.Errorf("leakix: invalid json: %w", err)
		}
		kind := "leak"
		if q.Params["scope"] == "service" {
			kind = "service"
		}
		for _, e := range events {
			page.Records = append(page.Records, eventToRecord(e, kind))
		}
	case registry.CapHostLookup:
		var host hostResponse
		if err := json.Unmarshal(resp.Body, &host); err != nil {
			return registry.Page{}, fmt.Errorf("leakix: invalid json: %w", err)
		}
		for _, e := range host.Services {
			page.Records = append(page.Records, eventToRecord(e, "service"))
		}
		for _, e := range host.Leaks {
			page.Records = append(page.Records, eventToRecord(e, "leak"))
		}
	case registry.CapSubdomainSearch:
		var subs []subdomain
		if err := json.Unmarshal(resp.Body, &subs); err != nil {
			return registry.Page{}, fmt.Errorf("leakix: invalid json: %w", err)
		}
		for _, s := range subs {
			rec := registry.Record{Kind: "domain", Value: s.Subdomain, Fields: map[string]string{"subdomain": s.Subdomain}}
			if s.LastSeen != "" {
				if t, err := time.Parse(time.RFC3339, s.LastSeen); err == nil {
					rec.ObservedAt = t.UTC()
				}
			}
			page.Records = append(page.Records, rec)
		}
	}
	return page, nil
}
