package asset

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type Kind string

const (
	KindDomain       Kind = "domain"
	KindHostname     Kind = "hostname"
	KindIP           Kind = "ip"
	KindCIDR         Kind = "cidr"
	KindURLRoot      Kind = "urlroot"
	KindCloud        Kind = "cloudresource"
	KindRepository   Kind = "repository"
	KindOrganization Kind = "organization"
	KindCertificate  Kind = "certificate"
	KindASN          Kind = "asn"
)

type Class string

const (
	ClassActive     Class = "active"
	ClassReportOnly Class = "reportonly"
	ClassWatchOnly  Class = "watchonly"
	ClassDenied     Class = "denied"
	ClassUnknown    Class = "unknown"
)

type OwnershipState string

const (
	OwnExact       OwnershipState = "exact"
	OwnInherited   OwnershipState = "inherited"
	OwnHistorical  OwnershipState = "historical"
	OwnSharedInfra OwnershipState = "sharedinfra"
	OwnCDNEdge     OwnershipState = "cdnedge"
	OwnCloudShared OwnershipState = "cloudshared"
	OwnUnknown     OwnershipState = "unknown"
)

type Asset struct {
	contracts.Versioned
	ID        string            `json:"id"`
	ProjectID string            `json:"projectId"`
	Kind      Kind              `json:"assetKind"`
	Value     string            `json:"value"`
	Class     Class             `json:"class"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	FirstSeen time.Time         `json:"firstSeen"`
	LastSeen  time.Time         `json:"lastSeen"`
}

func New(projectID string, kind Kind, value string) Asset {
	now := time.Now().UTC()
	return Asset{
		Versioned: contracts.NewVersioned("asset"),
		ID:        contracts.NewID("ast"),
		ProjectID: projectID,
		Kind:      kind,
		Value:     value,
		Class:     ClassUnknown,
		FirstSeen: now,
		LastSeen:  now,
	}
}

type ClaimConfidence struct {
	Parse      float64 `json:"parse"`
	Freshness  float64 `json:"freshness"`
	Directness float64 `json:"directness"`
}

type AssetClaim struct {
	contracts.Versioned
	ID         string          `json:"id"`
	AssetID    string          `json:"assetId"`
	ProjectID  string          `json:"projectId"`
	Source     string          `json:"source"`
	SourceID   string          `json:"sourceId,omitempty"`
	SourceURL  string          `json:"sourceUrl,omitempty"`
	ObservedAt time.Time       `json:"observedAt"`
	FetchedAt  time.Time       `json:"fetchedAt"`
	RawRef     string          `json:"rawRef,omitempty"`
	RawHash    string          `json:"rawHash,omitempty"`
	Confidence ClaimConfidence `json:"confidence"`
	Ownership  OwnershipState  `json:"ownership"`
}

type RelationKind string

const (
	RelResolvesTo RelationKind = "resolvesto"
	RelAliasOf    RelationKind = "aliasof"
	RelCertFor    RelationKind = "certfor"
	RelMemberOf   RelationKind = "memberof"
	RelHostedOn   RelationKind = "hostedon"
	RelPivot      RelationKind = "pivot"
)

type AssetRelation struct {
	contracts.Versioned
	ID          string       `json:"id"`
	ProjectID   string       `json:"projectId"`
	FromAssetID string       `json:"fromAssetId"`
	ToAssetID   string       `json:"toAssetId"`
	Kind        RelationKind `json:"relationKind"`
	EvidenceIDs []string     `json:"evidenceIds,omitempty"`
	ObservedAt  time.Time    `json:"observedAt"`
}
