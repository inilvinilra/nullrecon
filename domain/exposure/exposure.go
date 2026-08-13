package exposure

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/asset"
)

type Category string

const (
	CatOpenDatabase      Category = "opendatabase"
	CatDirListing        Category = "dirlisting"
	CatPublicBackup      Category = "publicbackup"
	CatDebugEndpoint     Category = "debugendpoint"
	CatRepoMetadata      Category = "repometadata"
	CatAdminInterface    Category = "admininterface"
	CatLeakedConfig      Category = "leakedconfig"
	CatObjectStore       Category = "objectstore"
	CatSourceMap         Category = "sourcemap"
	CatManagementService Category = "managementservice"
)

type Exposure struct {
	contracts.Versioned
	ID         string    `json:"id"`
	ProjectID  string    `json:"projectId"`
	AssetID    string    `json:"assetId"`
	Category   Category  `json:"category"`
	Title      string    `json:"title"`
	Source     string    `json:"source"`
	RawRef     string    `json:"rawRef,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
}

type Sensitivity string

const (
	SensLow      Sensitivity = "low"
	SensModerate Sensitivity = "moderate"
	SensHigh     Sensitivity = "high"
	SensCritical Sensitivity = "critical"
)

type Legality string

const (
	LegalPublicIndex  Legality = "publicindex"
	LegalApprovedFeed Legality = "approvedfeed"
	LegalRestricted   Legality = "restricted"
	LegalUnknown      Legality = "unknown"
)

type ValidationState string

const (
	ValUnverified   ValidationState = "unverified"
	ValFormatValid  ValidationState = "formatvalid"
	ValOfflineValid ValidationState = "offlinevalid"
	ValOnlineValid  ValidationState = "onlinevalid"
	ValInvalid      ValidationState = "invalid"
	ValRevoked      ValidationState = "revoked"
)

type RemediationState string

const (
	RemOpen       RemediationState = "open"
	RemNotified   RemediationState = "notified"
	RemRemediated RemediationState = "remediated"
	RemAccepted   RemediationState = "accepted"
)

type SecretCandidate struct {
	contracts.Versioned
	ID               string               `json:"id"`
	ProjectID        string               `json:"projectId"`
	AssetID          string               `json:"assetId,omitempty"`
	Detector         string               `json:"detector"`
	DetectorRevision string               `json:"detectorRevision"`
	Fingerprint      string               `json:"fingerprint"`
	Preview          string               `json:"preview"`
	ContextHash      string               `json:"contextHash"`
	Location         string               `json:"location"`
	Visibility       string               `json:"visibility"`
	Ownership        asset.OwnershipState `json:"ownership"`
	Legality         Legality             `json:"legality"`
	Sensitivity      Sensitivity          `json:"sensitivity"`
	Validation       ValidationState      `json:"validation"`
	Remediation      RemediationState     `json:"remediation"`
	FirstSeen        time.Time            `json:"firstSeen"`
	LastSeen         time.Time            `json:"lastSeen"`
}

func NewSecret(projectID, detector, revision, fingerprint, preview, contextHash, location string, seen time.Time) SecretCandidate {
	return SecretCandidate{
		Versioned:        contracts.NewVersioned("secretcandidate"),
		ID:               contracts.NewID("sec"),
		ProjectID:        projectID,
		Detector:         detector,
		DetectorRevision: revision,
		Fingerprint:      fingerprint,
		Preview:          preview,
		ContextHash:      contextHash,
		Location:         location,
		Ownership:        asset.OwnUnknown,
		Legality:         LegalUnknown,
		Sensitivity:      SensModerate,
		Validation:       ValUnverified,
		Remediation:      RemOpen,
		FirstSeen:        seen.UTC(),
		LastSeen:         seen.UTC(),
	}
}
