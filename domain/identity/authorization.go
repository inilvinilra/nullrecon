package identity

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type Authorization struct {
	contracts.Versioned
	ID           string    `json:"id"`
	ProjectID    string    `json:"projectId"`
	Source       string    `json:"source"`
	Reference    string    `json:"reference"`
	ProofRef     string    `json:"proofRef,omitempty"`
	AllowedModes []string  `json:"allowedModes"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidTo      time.Time `json:"validTo"`
	CreatedAt    time.Time `json:"createdAt"`
}

func NewAuthorization(projectID, source, reference string, modes []string, from, to time.Time) Authorization {
	return Authorization{
		Versioned:    contracts.NewVersioned("authorization"),
		ID:           contracts.NewID("authz"),
		ProjectID:    projectID,
		Source:       source,
		Reference:    reference,
		AllowedModes: modes,
		ValidFrom:    from.UTC(),
		ValidTo:      to.UTC(),
		CreatedAt:    time.Now().UTC(),
	}
}

func (a Authorization) ValidAt(t time.Time) bool {
	t = t.UTC()
	return !t.Before(a.ValidFrom) && !t.After(a.ValidTo)
}
