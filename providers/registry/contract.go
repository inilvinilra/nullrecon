package registry

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type AuthKind string

const (
	AuthNone   AuthKind = "none"
	AuthHeader AuthKind = "header"
	AuthQuery  AuthKind = "query"
)

type AuthSpec struct {
	Kind      AuthKind `json:"kind"`
	Header    string   `json:"header,omitempty"`
	QueryKey  string   `json:"queryKey,omitempty"`
	SecretRef string   `json:"secretRef,omitempty"`
	Required  bool     `json:"required"`
}

type RetryPolicy struct {
	MaxAttempts int `json:"maxAttempts"`
	BaseDelayMS int `json:"baseDelayMs"`
}

type Descriptor struct {
	contracts.Versioned
	Name            string       `json:"name"`
	AdapterVersion  string       `json:"adapterVersion"`
	Endpoint        string       `json:"endpoint"`
	Capabilities    []Capability `json:"capabilities"`
	Auth            AuthSpec     `json:"auth"`
	TierLimits      string       `json:"tierLimits"`
	QueryLimit      int          `json:"queryLimit"`
	Pagination      string       `json:"pagination"`
	CreditPerQuery  int64        `json:"creditPerQuery"`
	RatePerSecond   float64      `json:"ratePerSecond"`
	Retry           RetryPolicy  `json:"retry"`
	TimeoutSeconds  int          `json:"timeoutSeconds"`
	CacheTTLSeconds int          `json:"cacheTtlSeconds"`
	FreshnessClass  string       `json:"freshnessClass"`
	FieldCoverage   []string     `json:"fieldCoverage"`
	Terms           string       `json:"terms"`
	Redistribution  string       `json:"redistribution"`
	Normalization   string       `json:"normalization"`
}

func NewDescriptor(name, adapterVersion, endpoint string, caps []Capability) Descriptor {
	return Descriptor{
		Versioned:      contracts.Versioned{Kind: "providerdescriptor", Version: contracts.ProviderContractV1},
		Name:           name,
		AdapterVersion: adapterVersion,
		Endpoint:       endpoint,
		Capabilities:   caps,
		Normalization:  contracts.ProviderContractV1,
		Retry:          RetryPolicy{MaxAttempts: 3, BaseDelayMS: 500},
		TimeoutSeconds: 30,
		RatePerSecond:  1,
		CreditPerQuery: 1,
	}
}

type Query struct {
	Capability Capability        `json:"capability"`
	Params     map[string]string `json:"params"`
	Cursor     string            `json:"cursor,omitempty"`
	Limit      int               `json:"limit,omitempty"`
}

type RequestSpec struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body"`
}

type Record struct {
	Kind           string            `json:"kind"`
	Value          string            `json:"value"`
	Fields         map[string]string `json:"fields,omitempty"`
	ObservedAt     time.Time         `json:"observedAt"`
	FetchedAt      time.Time         `json:"fetchedAt"`
	SourceID       string            `json:"sourceId,omitempty"`
	SourceURL      string            `json:"sourceUrl,omitempty"`
	RawRef         string            `json:"rawRef,omitempty"`
	RawHash        string            `json:"rawHash,omitempty"`
	FreshnessClass string            `json:"freshnessClass"`
	AdapterVersion string            `json:"adapterVersion"`
}

type Page struct {
	Records    []Record `json:"records"`
	NextCursor string   `json:"nextCursor,omitempty"`
	Credits    int64    `json:"credits"`
}

type Adapter interface {
	Describe() Descriptor
	Build(q Query, secret string) (RequestSpec, error)
	Parse(q Query, resp Response) (Page, error)
}
