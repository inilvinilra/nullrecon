package contracts

const (
	SchemaV1           = "nr.schema/v1"
	ScopeV1            = "nr.scope/v1"
	ProviderContractV1 = "nr.provider/v1"
	EventV1            = "nr.event/v1"
	RuleSetV1          = "nr.rules/v1"
	ReportV1           = "nr.report/v1"
	EvidenceManifestV1 = "nr.evidence/v1"
)

type Versioned struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

func NewVersioned(kind string) Versioned {
	return Versioned{Kind: kind, Version: SchemaV1}
}
