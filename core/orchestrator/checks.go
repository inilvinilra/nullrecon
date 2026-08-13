package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nullrecon/nullrecon/analysis/confidence"
	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/asset"
	exposuredomain "github.com/nullrecon/nullrecon/domain/exposure"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
	"github.com/nullrecon/nullrecon/engines/exposure"
	"github.com/nullrecon/nullrecon/engines/secretscan"
	"github.com/nullrecon/nullrecon/engines/template"
	"github.com/nullrecon/nullrecon/reporting/redaction"
	"github.com/nullrecon/nullrecon/reporting/renderer"
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
	tmplSet, tmplErr := template.LoadEmbedded()
	var tmplEngine *template.Engine
	if tmplErr == nil {
		tmplEngine = template.New(nc.Snapshot, nc.Budget)
	}
	confirmed := 0
	secretCount := 0
	templateHits := 0
	bySeverity := map[string]int{}
	for _, target := range plan.Targets {
		res, err := engine.Scan(ctx, target.BaseURL)
		if err == nil {
			for _, f := range res.Findings {
				if err := o.recordExposure(ctx, nc, target.AssetID, f); err != nil {
					return nil, nil, err
				}
				confirmed++
				secretCount += len(f.Secrets)
				bySeverity[f.Severity]++
			}
		}
		if tmplEngine != nil {
			tres, terr := tmplEngine.Run(ctx, target.BaseURL, tmplSet)
			if terr == nil {
				for _, m := range tres.Matches {
					if err := o.recordTemplateMatch(ctx, nc, target.AssetID, m); err != nil {
						return nil, nil, err
					}
					templateHits++
					bySeverity[m.Severity]++
				}
			}
		}
	}
	return out(map[string]any{"exposures": confirmed, "secrets": secretCount, "templateHits": templateHits, "bySeverity": bySeverity})
}

func (o *Orchestrator) recordTemplateMatch(ctx context.Context, nc *workflow.NodeContext, assetID string, m template.Match) error {
	now := o.now()
	conf := finding.Confidence{
		Parse:              1.0,
		Ownership:          1.0,
		Freshness:          1.0,
		Fingerprint:        1.0,
		Version:            1.0,
		Prerequisite:       1.0,
		ActiveVerification: 1.0,
	}
	decision := confidence.DefaultModel().Decide(conf, nil)
	conf.Value = decision.Value
	conf.Gates = append([]string{"template:" + m.TemplateID}, decision.Gates...)
	if m.Prerequisite {
		conf.Gates = append(conf.Gates, "exploitability-prerequisite-unverified")
	}
	weakness := "template"
	if len(m.Tags) > 0 {
		weakness = "template:" + m.Tags[0]
	}
	key := "template:" + m.TemplateID + ":" + assetID
	title := m.Name
	if title == "" {
		title = m.TemplateID
	}
	fnd := finding.Finding{
		Versioned:       contracts.NewVersioned("finding"),
		ID:              contracts.NewID("fnd"),
		ProjectID:       nc.Run.ProjectID,
		Title:           title,
		State:           decision.State,
		Severity:        finding.Severity(m.Severity),
		Confidence:      conf,
		AssetIDs:        []string{assetID},
		ScopeSnapshotID: nc.Snapshot.ID,
		SnapshotHash:    nc.Snapshot.Hash,
		WeaknessClass:   weakness,
		Summary:         "Active template match at " + m.URL,
		FingerprintKey:  key,
		FirstSeen:       now,
		LastSeen:        now,
	}
	if m.CVE != "" {
		fnd.WeaknessClass = "vulnerability:template"
		fnd.Summary = "Active template verification of " + m.CVE + " at " + m.URL
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
	if m.CVE != "" {
		cand := vulnerability.New(nc.Run.ProjectID, assetID, vulnerability.MatchTemplate, "template", now)
		cand.CVE = m.CVE
		cand.VersionEvidence = m.URL
		cand.State = vulnerability.CandVerified
		if existing, ok, err := o.deps.DB.VulnCandidates().ByKey(ctx, assetID, m.CVE, vulnerability.MatchTemplate); err != nil {
			return err
		} else if ok {
			cand.ID = existing.ID
		}
		if err := o.deps.DB.VulnCandidates().Upsert(ctx, cand); err != nil {
			return err
		}
	}
	return nil
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
	conf := finding.Confidence{
		Parse:              1.0,
		Ownership:          1.0,
		Freshness:          1.0,
		Fingerprint:        1.0,
		Version:            1.0,
		Prerequisite:       1.0,
		ActiveVerification: 1.0,
	}
	decision := confidence.DefaultModel().Decide(conf, nil)
	conf.Value = decision.Value
	conf.Gates = append([]string{"content-verified"}, decision.Gates...)
	fnd := finding.Finding{
		Versioned:       contracts.NewVersioned("finding"),
		ID:              contracts.NewID("fnd"),
		ProjectID:       nc.Run.ProjectID,
		Title:           title,
		State:           decision.State,
		Severity:        finding.Severity(f.Severity),
		Confidence:      conf,
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

func (o *Orchestrator) renderReports(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	projectID := nc.Run.ProjectID
	findings, err := o.deps.DB.Findings().List(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	exposures, err := o.deps.DB.Exposures().ForProject(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	secrets, err := o.deps.DB.SecretCandidates().ForProject(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	vulns, err := o.deps.DB.VulnCandidates().ForProject(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	slug := ""
	if project, err := o.deps.DB.Projects().Get(ctx, projectID); err == nil {
		slug = project.Slug
	}
	data := renderer.New(projectID, slug, o.now())
	data.RunID = nc.Run.ID
	data.SnapshotHash = nc.Snapshot.Hash
	data.Mode = string(nc.Snapshot.Mode)
	data.Findings = findings
	data.ExposureCount = len(exposures)
	data.VulnerabilityCount = len(vulns)
	for _, v := range vulns {
		if v.KEV {
			data.KEVCount++
		}
	}
	summary := map[string]int{}
	for _, s := range secrets {
		summary[s.Detector]++
	}
	data.SecretSummary = summary
	report, err := renderer.RenderJSON(data)
	if err != nil {
		return nil, nil, err
	}
	ref := ""
	if o.deps.Raw != nil {
		if stored, err := o.deps.Raw.Put(report); err == nil {
			ref = stored
		}
	}
	return out(map[string]any{"findings": len(findings), "exposures": len(exposures), "secrets": len(secrets), "vulnerabilities": len(vulns), "kev": data.KEVCount, "severity": data.SeverityCounts(), "states": data.StateCounts(), "reportRef": ref})
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
