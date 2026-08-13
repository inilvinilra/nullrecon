package fofa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

var fofaFields = []string{"ip", "port", "protocol", "host", "title", "server", "cert", "lastupdatetime"}

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://fofa.info"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("fofa", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapAssetSearch,
		registry.CapServiceSearch,
		registry.CapCertificateSearch,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthQuery, SecretRef: "provider/fofa", Required: true}
	d.Pagination = "single-page"
	d.FreshnessClass = "daily"
	d.FieldCoverage = []string{"ip", "port", "protocol", "host", "title", "server", "cert", "lastupdatetime"}
	d.Terms = "https://fofa.info/terms"
	d.Redistribution = "attribution required; verify current terms"
	d.CacheTTLSeconds = 3600
	return d
}

type apiResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`
	Results [][]string `json:"results"`
	Mode    string     `json:"mode"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	if secret == "" {
		return registry.RequestSpec{}, registry.ErrAuthMissing
	}
	email, key, ok := strings.Cut(secret, ":")
	if !ok || email == "" || key == "" {
		return registry.RequestSpec{}, fmt.Errorf("fofa: credential must be stored as email:key")
	}
	queryText := q.Params["q"]
	if queryText == "" {
		return registry.RequestSpec{}, fmt.Errorf("fofa: query param q is required")
	}
	size := q.Limit
	if size <= 0 || size > 100 {
		size = 100
	}
	return registry.RequestSpec{
		Method: "GET",
		Path:   "/api/v1/search/all",
		Query: map[string]string{
			"email":   email,
			"key":     key,
			"qbase64": base64.StdEncoding.EncodeToString([]byte(queryText)),
			"size":    strconv.Itoa(size),
			"fields":  strings.Join(fofaFields, ","),
		},
	}, nil
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed apiResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("fofa: invalid json: %w", err)
	}
	if parsed.Error {
		return registry.Page{}, fmt.Errorf("fofa: api error: %s", parsed.ErrMsg)
	}
	page := registry.Page{Credits: 1}
	for _, row := range parsed.Results {
		if len(row) != len(fofaFields) {
			return registry.Page{}, fmt.Errorf("fofa: unexpected result column count %d", len(row))
		}
		rec := registry.Record{Kind: "service", Fields: map[string]string{}}
		for i, field := range fofaFields {
			value := row[i]
			switch field {
			case "ip":
				rec.Value = value
				rec.Fields["ip"] = value
			case "host":
				rec.Fields["host"] = value
				if rec.Value == "" {
					rec.Value = value
				}
			case "lastupdatetime":
				if t, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
					rec.ObservedAt = t.UTC()
				} else if t, err := time.Parse("2006-01-02", value); err == nil {
					rec.ObservedAt = t.UTC()
				}
			case "cert":
				rec.Fields["cert"] = hashIfLong(value)
			default:
				rec.Fields[field] = value
			}
		}
		page.Records = append(page.Records, rec)
	}
	return page, nil
}

func hashIfLong(value string) string {
	if len(value) <= 128 {
		return value
	}
	sum := sha256Of(value)
	return "sha256:" + sum
}
