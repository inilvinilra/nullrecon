package finding

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type State string

const (
	StateConfirmed     State = "confirmed"
	StateLikely        State = "likely"
	StatePotential     State = "potential"
	StateInformational State = "informational"
	StateFalsePositive State = "falsepositive"
	StateStale         State = "stale"
	StateDuplicate     State = "duplicate"
	StateOutOfScope    State = "outofscope"
	StateNeedsReview   State = "needsreview"
)

type Confidence struct {
	Parse              float64  `json:"parse"`
	Ownership          float64  `json:"ownership"`
	Freshness          float64  `json:"freshness"`
	Fingerprint        float64  `json:"fingerprint"`
	Version            float64  `json:"version"`
	Prerequisite       float64  `json:"prerequisite"`
	CrossSource        float64  `json:"crossSource"`
	ActiveVerification float64  `json:"activeVerification"`
	DeceptionPenalty   float64  `json:"deceptionPenalty"`
	SharedInfraPenalty float64  `json:"sharedInfraPenalty"`
	GatewayPenalty     float64  `json:"gatewayPenalty"`
	StalenessPenalty   float64  `json:"stalenessPenalty"`
	Gates              []string `json:"gates,omitempty"`
	Value              float64  `json:"value"`
}

type Finding struct {
	contracts.Versioned
	ID              string     `json:"id"`
	ProjectID       string     `json:"projectId"`
	Title           string     `json:"title"`
	State           State      `json:"state"`
	Severity        Severity   `json:"severity"`
	Confidence      Confidence `json:"confidence"`
	AssetIDs        []string   `json:"assetIds"`
	EndpointIDs     []string   `json:"endpointIds,omitempty"`
	ObservationIDs  []string   `json:"observationIds"`
	EvidenceIDs     []string   `json:"evidenceIds,omitempty"`
	ScopeSnapshotID string     `json:"scopeSnapshotId"`
	SnapshotHash    string     `json:"snapshotHash"`
	WeaknessClass   string     `json:"weaknessClass,omitempty"`
	Summary         string     `json:"summary,omitempty"`
	Impact          string     `json:"impact,omitempty"`
	Remediation     string     `json:"remediation,omitempty"`
	FingerprintKey  string     `json:"fingerprintKey"`
	FirstSeen       time.Time  `json:"firstSeen"`
	LastSeen        time.Time  `json:"lastSeen"`
}

type RelationKind string

const (
	FindingDuplicateOf RelationKind = "duplicateof"
	FindingRecurs      RelationKind = "recurs"
	FindingSupersedes  RelationKind = "supersedes"
)

type Relation struct {
	contracts.Versioned
	ID         string       `json:"id"`
	ProjectID  string       `json:"projectId"`
	FromID     string       `json:"fromId"`
	ToID       string       `json:"toId"`
	Kind       RelationKind `json:"relationKind"`
	ReasonCode string       `json:"reasonCode"`
	CreatedAt  time.Time    `json:"createdAt"`
}
