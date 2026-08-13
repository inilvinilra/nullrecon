package technology

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type EvidenceRef struct {
	Kind   string  `json:"kind"`
	Detail string  `json:"detail"`
	Weight float64 `json:"weight"`
}

type Technology struct {
	contracts.Versioned
	ID         string        `json:"id"`
	ProjectID  string        `json:"projectId"`
	AssetID    string        `json:"assetId"`
	EndpointID string        `json:"endpointId,omitempty"`
	Product    string        `json:"product"`
	Vendor     string        `json:"vendor,omitempty"`
	Version    string        `json:"version,omitempty"`
	Constraint string        `json:"constraint,omitempty"`
	CPE        []string      `json:"cpe,omitempty"`
	Package    string        `json:"package,omitempty"`
	Method     string        `json:"method"`
	Confidence float64       `json:"confidence"`
	Evidence   []EvidenceRef `json:"evidence,omitempty"`
	ObservedAt time.Time     `json:"observedAt"`
}

func New(projectID, assetID, product, method string, observed time.Time) Technology {
	return Technology{
		Versioned:  contracts.NewVersioned("technology"),
		ID:         contracts.NewID("tech"),
		ProjectID:  projectID,
		AssetID:    assetID,
		Product:    product,
		Method:     method,
		ObservedAt: observed.UTC(),
	}
}
