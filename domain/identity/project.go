package identity

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type ProjectStatus string

const (
	ProjectActive    ProjectStatus = "active"
	ProjectSuspended ProjectStatus = "suspended"
	ProjectArchived  ProjectStatus = "archived"
)

type RetentionPolicy struct {
	EvidenceDays    int `json:"evidenceDays"`
	ObservationDays int `json:"observationDays"`
	RawArtifactDays int `json:"rawArtifactDays"`
	AuditDays       int `json:"auditDays"`
}

type RedactionPolicy struct {
	Profile           string   `json:"profile"`
	ExtraPatterns     []string `json:"extraPatterns,omitempty"`
	FingerprintKeyRef string   `json:"fingerprintKeyRef"`
}

type Project struct {
	contracts.Versioned
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Status    ProjectStatus   `json:"status"`
	Retention RetentionPolicy `json:"retention"`
	Redaction RedactionPolicy `json:"redaction"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

func NewProject(name, slug string) Project {
	now := time.Now().UTC()
	return Project{
		Versioned: contracts.NewVersioned("project"),
		ID:        contracts.NewID("prj"),
		Name:      name,
		Slug:      slug,
		Status:    ProjectActive,
		Retention: RetentionPolicy{EvidenceDays: 365, ObservationDays: 180, RawArtifactDays: 90, AuditDays: 730},
		Redaction: RedactionPolicy{Profile: "default", FingerprintKeyRef: "project-fingerprint"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}
