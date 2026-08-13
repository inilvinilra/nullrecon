package evidence

import (
	"time"

	"github.com/nullrecon/nullrecon/contracts"
)

type Kind string

const (
	KindHTTPTranscript Kind = "httptranscript"
	KindToolOutput     Kind = "tooloutput"
	KindProviderRecord Kind = "providerrecord"
	KindDNSAnswer      Kind = "dnsanswer"
	KindTLSState       Kind = "tlsstate"
	KindVerifierOutput Kind = "verifieroutput"
	KindManifest       Kind = "manifest"
)

type Provenance struct {
	SourceID       string `json:"sourceId,omitempty"`
	SourceURL      string `json:"sourceUrl,omitempty"`
	Adapter        string `json:"adapter,omitempty"`
	AdapterVersion string `json:"adapterVersion,omitempty"`
}

type Evidence struct {
	contracts.Versioned
	ID             string            `json:"id"`
	ProjectID      string            `json:"projectId"`
	FindingID      string            `json:"findingId,omitempty"`
	RunID          string            `json:"runId,omitempty"`
	Kind           Kind              `json:"evidenceKind"`
	CapturedAt     time.Time         `json:"capturedAt"`
	Tool           string            `json:"tool,omitempty"`
	ToolVersion    string            `json:"toolVersion,omitempty"`
	RequestMeta    map[string]string `json:"requestMeta,omitempty"`
	ResponseMeta   map[string]string `json:"responseMeta,omitempty"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	StorageRef     string            `json:"storageRef"`
	SizeBytes      int64             `json:"sizeBytes"`
	RedactionState string            `json:"redactionState"`
	Provenance     Provenance        `json:"provenance,omitempty"`
}

type ManifestEntry struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type Manifest struct {
	contracts.Versioned
	ID         string          `json:"id"`
	ProjectID  string          `json:"projectId"`
	EvidenceID string          `json:"evidenceId"`
	Entries    []ManifestEntry `json:"entries"`
	SealedAt   time.Time       `json:"sealedAt"`
}

func NewManifest(projectID, evidenceID string, entries []ManifestEntry) Manifest {
	return Manifest{
		Versioned:  contracts.Versioned{Kind: "manifest", Version: contracts.EvidenceManifestV1},
		ID:         contracts.NewID("man"),
		ProjectID:  projectID,
		EvidenceID: evidenceID,
		Entries:    entries,
		SealedAt:   time.Now().UTC(),
	}
}
