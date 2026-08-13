package nvd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/providers/registry"
)

const adapterVersion = "1.0.0"

const resultsPerPage = 2000

type Adapter struct {
	endpoint string
}

func New(endpointOverride string) *Adapter {
	endpoint := "https://services.nvd.nist.gov"
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return &Adapter{endpoint: endpoint}
}

func (a *Adapter) Describe() registry.Descriptor {
	d := registry.NewDescriptor("nvd", adapterVersion, a.endpoint, []registry.Capability{
		registry.CapCVELookup,
		registry.CapCPELookup,
	})
	d.Auth = registry.AuthSpec{Kind: registry.AuthHeader, Header: "apiKey", SecretRef: "provider/nvd", Required: false}
	d.Pagination = "offset"
	d.FreshnessClass = "daily"
	d.QueryLimit = resultsPerPage
	d.RatePerSecond = 0.4
	d.FieldCoverage = []string{"cve", "cvss", "severity", "cpe", "versionRange", "published", "lastModified"}
	d.Terms = "https://nvd.nist.gov/developers/terms-of-use"
	d.Redistribution = "public domain data; attribution requested"
	d.CacheTTLSeconds = 21600
	d.Retry = registry.RetryPolicy{MaxAttempts: 5, BaseDelayMS: 8000}
	return d
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type configNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type configuration struct {
	Nodes []configNode `json:"nodes"`
}

type cvssData struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cvssMetric struct {
	CVSSData cvssData `json:"cvssData"`
}

type metrics struct {
	V31 []cvssMetric `json:"cvssMetricV31"`
	V30 []cvssMetric `json:"cvssMetricV30"`
	V2  []cvssMetric `json:"cvssMetricV2"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cveItem struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	VulnStatus     string          `json:"vulnStatus"`
	Descriptions   []description   `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Configurations []configuration `json:"configurations"`
}

type vulnerability struct {
	CVE cveItem `json:"cve"`
}

type searchResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

func (a *Adapter) Build(q registry.Query, secret string) (registry.RequestSpec, error) {
	query := map[string]string{"resultsPerPage": strconv.Itoa(resultsPerPage)}
	switch q.Capability {
	case registry.CapCVELookup:
		switch {
		case q.Params["cveId"] != "":
			query["cveId"] = q.Params["cveId"]
		case q.Params["cpeName"] != "":
			query["cpeName"] = q.Params["cpeName"]
		case q.Params["keyword"] != "":
			query["keywordSearch"] = q.Params["keyword"]
		case q.Params["lastModStartDate"] != "":
			query["lastModStartDate"] = q.Params["lastModStartDate"]
			if q.Params["lastModEndDate"] != "" {
				query["lastModEndDate"] = q.Params["lastModEndDate"]
			}
		case q.Params["pubStartDate"] != "":
			query["pubStartDate"] = q.Params["pubStartDate"]
			if q.Params["pubEndDate"] != "" {
				query["pubEndDate"] = q.Params["pubEndDate"]
			}
		default:
			return registry.RequestSpec{}, fmt.Errorf("nvd: one of cveId, cpeName, keyword, or lastModStartDate is required")
		}
	case registry.CapCPELookup:
		if q.Params["cpeName"] == "" {
			return registry.RequestSpec{}, fmt.Errorf("nvd: param cpeName is required")
		}
		query["cpeName"] = q.Params["cpeName"]
	default:
		return registry.RequestSpec{}, fmt.Errorf("nvd: capability %s not supported", q.Capability)
	}
	if q.Cursor != "" {
		start, err := strconv.Atoi(q.Cursor)
		if err != nil || start < 0 {
			return registry.RequestSpec{}, fmt.Errorf("nvd: invalid cursor")
		}
		query["startIndex"] = strconv.Itoa(start)
	}
	spec := registry.RequestSpec{Method: "GET", Path: "/rest/json/cves/2.0", Query: query}
	if secret != "" {
		spec.Headers = map[string]string{"apiKey": secret}
	}
	return spec, nil
}

func pickCVSS(m metrics) (cvssData, bool) {
	if len(m.V31) > 0 {
		return m.V31[0].CVSSData, true
	}
	if len(m.V30) > 0 {
		return m.V30[0].CVSSData, true
	}
	if len(m.V2) > 0 {
		return m.V2[0].CVSSData, true
	}
	return cvssData{}, false
}

func englishDescription(items []description) string {
	for _, d := range items {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(items) > 0 {
		return items[0].Value
	}
	return ""
}

func collectRanges(configs []configuration) []cpeMatch {
	var out []cpeMatch
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CPEMatch {
				if m.Vulnerable && m.Criteria != "" {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

func (a *Adapter) itemToRecord(item cveItem) registry.Record {
	rec := registry.Record{
		Kind:           "cve",
		Value:          item.ID,
		Fields:         map[string]string{"cve": item.ID},
		AdapterVersion: adapterVersion,
	}
	if desc := englishDescription(item.Descriptions); desc != "" {
		rec.Fields["description"] = desc
	}
	if item.VulnStatus != "" {
		rec.Fields["status"] = item.VulnStatus
	}
	if cvss, ok := pickCVSS(item.Metrics); ok {
		rec.Fields["cvssScore"] = strconv.FormatFloat(cvss.BaseScore, 'f', -1, 64)
		rec.Fields["cvssVector"] = cvss.VectorString
		rec.Fields["severity"] = strings.ToLower(cvss.BaseSeverity)
	}
	if ranges := collectRanges(item.Configurations); len(ranges) > 0 {
		if encoded, err := json.Marshal(ranges); err == nil {
			rec.Fields["cpeRanges"] = string(encoded)
		}
	}
	if item.Published != "" {
		rec.Fields["published"] = item.Published
	}
	if t, err := time.Parse("2006-01-02T15:04:05.000", item.LastModified); err == nil {
		rec.ObservedAt = t.UTC()
		rec.Fields["lastModified"] = item.LastModified
	}
	return rec
}

func (a *Adapter) Parse(q registry.Query, resp registry.Response) (registry.Page, error) {
	var parsed searchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return registry.Page{}, fmt.Errorf("nvd: invalid json: %w", err)
	}
	page := registry.Page{Credits: 1}
	for _, v := range parsed.Vulnerabilities {
		page.Records = append(page.Records, a.itemToRecord(v.CVE))
	}
	next := parsed.StartIndex + parsed.ResultsPerPage
	if next < parsed.TotalResults {
		page.NextCursor = strconv.Itoa(next)
	}
	return page, nil
}
