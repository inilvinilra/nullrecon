package endpoint

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type AuthState string

const (
	AuthNone     AuthState = "none"
	AuthRequired AuthState = "required"
	AuthSession  AuthState = "session"
	AuthUnknown  AuthState = "unknown"
)

type Endpoint struct {
	contracts.Versioned
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	AssetID     string    `json:"assetId"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Params      []string  `json:"params,omitempty"`
	ContentType string    `json:"contentType,omitempty"`
	Auth        AuthState `json:"auth"`
	Status      int       `json:"status,omitempty"`
	ContentHash string    `json:"contentHash,omitempty"`
	Source      string    `json:"source"`
	ObservedAt  time.Time `json:"observedAt"`
}

func New(projectID, assetID, rawURL, method, source string, observed time.Time) Endpoint {
	return Endpoint{
		Versioned:  contracts.NewVersioned("endpoint"),
		ID:         contracts.NewID("ept"),
		ProjectID:  projectID,
		AssetID:    assetID,
		URL:        rawURL,
		Method:     method,
		Auth:       AuthUnknown,
		Source:     source,
		ObservedAt: observed.UTC(),
	}
}
