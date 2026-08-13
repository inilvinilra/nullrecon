package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/asset"
	exposuredomain "github.com/nullrecon/nullrecon/domain/exposure"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/engines/exposure"
	"github.com/nullrecon/nullrecon/engines/secretscan"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

func (o *Orchestrator) generateVulnerabilityCandidates(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	targets, err := o.webTargets(ctx, nc, policy.ActionVulnTemplate)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return out(map[string]any{"targets": targets, "note": "active checks not authorized or no web targets"})
	}
	return out(map[string]any{"targets": targets})
}

func (o *Orchestrator) runAllowedChecks(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var plan struct {
		Targets []discoveryTarget `json:"targets"`
	}
	if err := inputAt(nc, "GenerateVulnerabilityCandidates", &plan); err != nil {
		return out(map[string]any{"exposures": 0})
	}
	if len(plan.Targets) == 0 {
		return out(map[string]any{"exposures": 0, "note": "no authorized web targets"})
	}
	set, err := exposure.LoadSignatures()
	if err != nil {
		return nil, nil, err
	}
	red, err := redaction.New(nil)
	if err != nil {
		return nil, nil, err
	}
	engine := exposure.New(nc.Snapshot, nc.Budget, red, set)
	if detectors, err := secretscan.DefaultDetectors(); err == nil {
		engine.WithSecretDetectors(detectors)
	}
	confirmed := 0
	secretCount := 0
	bySeverity := map[string]int{}
	for _, target := range plan.Targets {
		res, err := engine.Scan(ctx, target.BaseURL)
		if err != nil {
			continue
		}
		for _, f := range res.Findings {
			if err := o.recordExposure(ctx, nc, target.AssetID, f); err != nil {
				return nil, nil, err
			}
			confirmed++
			secretCount += len(f.Secrets)
			bySeverity[f.Severity]++
		}
	}
	return out(map[string]any{"exposures": confirmed, "secrets": secretCount, "bySeverity": bySeverity})
}

func (o *Orchestrator) recordExposure(ctx context.Context, nc *workflow.NodeContext, assetID string, f exposure.Finding) error {
	now := o.now()
	title := fmt.Sprintf("Exposed %s at %s", f.SignatureID, f.URL)
	exp := exposuredomain.Exposure{
		Versioned:  contracts.NewVersioned("exposure"),
		ID:         contracts.NewID("exp"),
		ProjectID:  nc.Run.ProjectID,
		AssetID:    assetID,
		Category:   categoryFor(f),
		Title:      title,
		Source:     "exposure",
		ObservedAt: now,
	}
	if err := o.deps.DB.Exposures().Put(ctx, exp); err != nil {
		return err
	}
	key := "exposure:" + f.SignatureID + ":" + assetID
	fnd := finding.Finding{
		Versioned:       contracts.NewVersioned("finding"),
		ID:              contracts.NewID("fnd"),
		ProjectID:       nc.Run.ProjectID,
		Title:           title,
		State:           finding.StateConfirmed,
		Severity:        finding.Severity(f.Severity),
		Confidence:      finding.Confidence{ActiveVerification: 1.0, Value: confidenceFor(f.Severity), Gates: []string{"content-verified"}},
		AssetIDs:        []string{assetID},
		ScopeSnapshotID: nc.Snapshot.ID,
		SnapshotHash:    nc.Snapshot.Hash,
		WeaknessClass:   "exposure:" + f.Category,
		Summary:         fmt.Sprintf("Content-verified %s exposure (%s)", f.Category, f.SignatureID),
		FingerprintKey:  key,
		FirstSeen:       now,
		LastSeen:        now,
	}
	if existing, ok, err := o.deps.DB.Findings().ByFingerprint(ctx, nc.Run.ProjectID, key); err != nil {
		return err
	} else if ok {
		fnd.ID = existing.ID
		fnd.FirstSeen = existing.FirstSeen
	}
	if err := o.deps.DB.Findings().Upsert(ctx, fnd); err != nil {
		return err
	}
	for _, hit := range f.Secrets {
		if err := o.recordSecret(ctx, nc, assetID, f.URL, hit); err != nil {
			return err
		}
	}
	return nil
}

func (o *Orchestrator) recordSecret(ctx context.Context, nc *workflow.NodeContext, assetID, location string, hit exposure.SecretHit) error {
	now := o.now()
	candidate := exposuredomain.NewSecret(nc.Run.ProjectID, hit.DetectorID, secretscan.DetectorsVersion, hit.Fingerprint, hit.Preview, "", location, now)
	candidate.AssetID = assetID
	candidate.Ownership = asset.OwnExact
	candidate.Sensitivity = sensitivityFor(hit.Severity)
	candidate.Validation = exposuredomain.ValFormatValid
	if existing, ok, err := o.deps.DB.SecretCandidates().ByFingerprint(ctx, nc.Run.ProjectID, hit.DetectorID, hit.Fingerprint, location); err != nil {
		return err
	} else if ok {
		candidate.ID = existing.ID
		candidate.FirstSeen = existing.FirstSeen
	}
	return o.deps.DB.SecretCandidates().Upsert(ctx, candidate)
}

func sensitivityFor(severity string) exposuredomain.Sensitivity {
	switch severity {
	case "critical":
		return exposuredomain.SensCritical
	case "high":
		return exposuredomain.SensHigh
	case "medium":
		return exposuredomain.SensModerate
	}
	return exposuredomain.SensLow
}

func categoryFor(f exposure.Finding) exposuredomain.Category {
	switch f.SignatureID {
	case "git-config", "git-head":
		return exposuredomain.CatRepoMetadata
	case "sql-dump", "wp-config-backup":
		return exposuredomain.CatPublicBackup
	case "directory-listing":
		return exposuredomain.CatDirListing
	case "spring-actuator-env", "spring-heapdump", "phpinfo", "server-status":
		return exposuredomain.CatDebugEndpoint
	}
	if f.Category == "leak" {
		return exposuredomain.CatLeakedConfig
	}
	return exposuredomain.CatDebugEndpoint
}

func confidenceFor(severity string) float64 {
	switch severity {
	case "critical", "high":
		return 0.95
	case "medium":
		return 0.9
	}
	return 0.85
}
