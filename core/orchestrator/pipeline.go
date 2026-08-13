package orchestrator

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/nullrecon/nullrecon/analysis/confidence"
	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/evidence"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/technology"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
	"github.com/nullrecon/nullrecon/engines/vulnmatch"
)

func (o *Orchestrator) collectLeakSignals(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	secrets, err := o.deps.DB.SecretCandidates().ForProject(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	byDetector := map[string]int{}
	for _, s := range secrets {
		byDetector[s.Detector]++
	}
	return out(map[string]any{"signals": len(secrets), "byDetector": byDetector})
}

func (o *Orchestrator) scanApprovedRepositories(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	return out(map[string]any{"repositories": 0, "note": "no approved repositories configured for this scope"})
}

func (o *Orchestrator) enrichVulnerabilities(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	set, err := vulnmatch.LoadRules()
	if err != nil {
		return nil, nil, err
	}
	techs, err := o.deps.DB.Technologies().ForProject(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	engine := vulnmatch.New(set)
	storeMatcher := vulnmatch.NewStoreMatcher()
	candidates := 0
	fromStore := 0
	kev := 0
	bySeverity := map[string]int{}
	record := func(tech technology.Technology, cand vulnerability.Candidate) error {
		sev := severityForCandidate(cand)
		if err := o.recordVulnCandidate(ctx, nc, tech, cand, sev); err != nil {
			return err
		}
		candidates++
		if cand.KEV {
			kev++
		}
		bySeverity[string(sev)]++
		return nil
	}
	seen := map[string]bool{}
	for _, tech := range techs {
		for _, cand := range engine.Match(nc.Run.ProjectID, tech) {
			if err := record(tech, cand); err != nil {
				return nil, nil, err
			}
			seen[cand.AssetID+"|"+cand.CVE] = true
		}
		records, err := o.deps.DB.CVEKnowledge().ForProduct(ctx, tech.Product)
		if err != nil {
			return nil, nil, err
		}
		for _, cand := range storeMatcher.Match(nc.Run.ProjectID, tech, records) {
			if seen[cand.AssetID+"|"+cand.CVE] {
				continue
			}
			seen[cand.AssetID+"|"+cand.CVE] = true
			if err := record(tech, cand); err != nil {
				return nil, nil, err
			}
			fromStore++
		}
	}
	return out(map[string]any{"technologies": len(techs), "candidates": candidates, "fromStore": fromStore, "kev": kev, "bySeverity": bySeverity})
}

func (o *Orchestrator) recordVulnCandidate(ctx context.Context, nc *workflow.NodeContext, tech technology.Technology, cand vulnerability.Candidate, sev finding.Severity) error {
	if existing, ok, err := o.deps.DB.VulnCandidates().ByKey(ctx, cand.AssetID, cand.CVE, cand.MatchedBy); err != nil {
		return err
	} else if ok {
		cand.ID = existing.ID
	}
	if err := o.deps.DB.VulnCandidates().Upsert(ctx, cand); err != nil {
		return err
	}
	now := o.now()
	fingerprintConf := tech.Confidence
	if fingerprintConf <= 0 {
		fingerprintConf = 0.6
	}
	conf := finding.Confidence{
		Parse:              1.0,
		Ownership:          1.0,
		Freshness:          0.7,
		Fingerprint:        fingerprintConf,
		Version:            fingerprintConf,
		Prerequisite:       0.0,
		ActiveVerification: 0.0,
		CrossSource:        0.0,
	}
	decision := confidence.DefaultModel().Decide(conf, []string{"parse", "ownership"})
	conf.Value = decision.Value
	conf.Gates = append([]string{"version-inferred", "prerequisite-unverified"}, decision.Gates...)
	key := "vuln:" + cand.CVE + ":" + cand.AssetID
	title := cand.CVE + " affects " + tech.Product + " " + tech.Version
	fnd := finding.Finding{
		Versioned:       contracts.NewVersioned("finding"),
		ID:              contracts.NewID("fnd"),
		ProjectID:       nc.Run.ProjectID,
		Title:           title,
		State:           decision.State,
		Severity:        sev,
		Confidence:      conf,
		AssetIDs:        []string{cand.AssetID},
		ScopeSnapshotID: nc.Snapshot.ID,
		SnapshotHash:    nc.Snapshot.Hash,
		WeaknessClass:   "vulnerability:" + string(cand.MatchedBy),
		Summary:         "Version-range match against " + cand.CVE + "; prerequisites unverified and no active confirmation",
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
	return o.deps.DB.Findings().Upsert(ctx, fnd)
}

func severityForCandidate(c vulnerability.Candidate) finding.Severity {
	score := 0.0
	if c.CVSS != nil {
		score = c.CVSS.Score
	}
	switch {
	case score >= 9.0:
		return finding.SevCritical
	case score >= 7.0:
		return finding.SevHigh
	case score >= 4.0:
		return finding.SevMedium
	case score > 0:
		return finding.SevLow
	}
	return finding.SevInfo
}

func (o *Orchestrator) deduplicateSignals(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]int{}
	duplicates := 0
	for _, f := range findings {
		seen[f.FingerprintKey]++
		if seen[f.FingerprintKey] > 1 {
			duplicates++
		}
	}
	return out(map[string]any{"findings": len(findings), "unique": len(seen), "duplicates": duplicates})
}

func (o *Orchestrator) verifyCandidates(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	candidates, err := o.deps.DB.VulnCandidates().ForProject(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	activeCorroboration := map[string]bool{}
	for _, c := range candidates {
		if c.MatchedBy == vulnerability.MatchTemplate || c.State == vulnerability.CandVerified {
			activeCorroboration[c.AssetID+"|"+c.CVE] = true
		}
	}
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	model := confidence.DefaultModel()
	upgraded := 0
	alreadyActive := 0
	for _, f := range findings {
		cve, asset, ok := parseVulnKey(f.FingerprintKey)
		if !ok {
			continue
		}
		if f.Confidence.ActiveVerification >= 0.8 {
			alreadyActive++
			continue
		}
		if !activeCorroboration[asset+"|"+cve] {
			continue
		}
		f.Confidence.ActiveVerification = 1.0
		f.Confidence.CrossSource = 0.6
		f.Confidence.Prerequisite = 1.0
		f.Confidence.Fingerprint = 1.0
		f.Confidence.Version = 1.0
		decision := model.Decide(f.Confidence, mandatoryFor(f))
		f.State = decision.State
		f.Confidence.Value = decision.Value
		f.Confidence.Gates = mergeGates(f.Confidence.Gates, append([]string{"active-template-corroborated"}, decision.Gates...))
		if err := o.deps.DB.Findings().Upsert(ctx, f); err != nil {
			return nil, nil, err
		}
		upgraded++
	}
	return out(map[string]any{"candidates": len(candidates), "activeCorroborations": len(activeCorroboration), "upgraded": upgraded, "alreadyActive": alreadyActive})
}

func parseVulnKey(key string) (cve, asset string, ok bool) {
	if !strings.HasPrefix(key, "vuln:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(key, "vuln:")
	idx := strings.LastIndex(rest, ":")
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

func (o *Orchestrator) scoreConfidence(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	model := confidence.DefaultModel()
	byState := map[string]int{}
	changed := 0
	for _, f := range findings {
		decision := model.Decide(f.Confidence, mandatoryFor(f))
		byState[string(decision.State)]++
		if f.State == decision.State && f.Confidence.Value == decision.Value {
			continue
		}
		f.State = decision.State
		f.Confidence.Value = decision.Value
		f.Confidence.Gates = mergeGates(f.Confidence.Gates, decision.Gates)
		if err := o.deps.DB.Findings().Upsert(ctx, f); err != nil {
			return nil, nil, err
		}
		changed++
	}
	return out(map[string]any{"scored": len(findings), "updated": changed, "byState": byState})
}

func (o *Orchestrator) prioritizeFindings(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := severityWeight(findings[i].Severity), severityWeight(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].Confidence.Value > findings[j].Confidence.Value
	})
	type ranked struct {
		ID       string  `json:"id"`
		Title    string  `json:"title"`
		Severity string  `json:"severity"`
		State    string  `json:"state"`
		Value    float64 `json:"value"`
	}
	top := make([]ranked, 0, len(findings))
	for _, f := range findings {
		if f.State == finding.StateFalsePositive || f.State == finding.StateOutOfScope || f.State == finding.StateDuplicate {
			continue
		}
		top = append(top, ranked{ID: f.ID, Title: f.Title, Severity: string(f.Severity), State: string(f.State), Value: f.Confidence.Value})
	}
	return out(map[string]any{"prioritized": len(top), "findings": top})
}

func (o *Orchestrator) buildEvidence(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	findings, err := o.deps.DB.Findings().List(ctx, nc.Run.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	now := o.now()
	prevChain := nc.Snapshot.Hash
	built := 0
	skipped := 0
	for _, f := range findings {
		if has, err := o.hasRunEvidence(ctx, f.ID, nc.Run.ID); err != nil {
			return nil, nil, err
		} else if has {
			skipped++
			continue
		}
		payload := evidencePayload(f, nc.Snapshot.Hash)
		contentHash := contracts.HashBytes(payload)
		chain := contracts.HashBytes([]byte(prevChain + contentHash))
		ev := evidence.Evidence{
			Versioned:   contracts.NewVersioned("evidence"),
			ID:          contracts.NewID("evd"),
			ProjectID:   nc.Run.ProjectID,
			FindingID:   f.ID,
			RunID:       nc.Run.ID,
			Kind:        evidence.KindVerifierOutput,
			CapturedAt:  now,
			Tool:        "nullrecon",
			ToolVersion: "0.1",
			ResponseMeta: map[string]string{
				"state":      string(f.State),
				"severity":   string(f.Severity),
				"confidence": strconv.FormatFloat(f.Confidence.Value, 'f', 2, 64),
			},
			Hashes:         map[string]string{"content": contentHash, "chain": chain, "prev": prevChain},
			RedactionState: "redacted",
			SizeBytes:      int64(len(payload)),
		}
		ev.StorageRef = contentHash
		if o.deps.Raw != nil {
			if ref, err := o.deps.Raw.Put(payload); err == nil {
				ev.StorageRef = ref
			}
		}
		if err := o.deps.DB.Evidence().Put(ctx, ev); err != nil {
			return nil, nil, err
		}
		f.EvidenceIDs = append(f.EvidenceIDs, ev.ID)
		if err := o.deps.DB.Findings().Upsert(ctx, f); err != nil {
			return nil, nil, err
		}
		prevChain = chain
		built++
	}
	return out(map[string]any{"findings": len(findings), "evidenceBuilt": built, "skipped": skipped, "chainHead": prevChain})
}

func (o *Orchestrator) hasRunEvidence(ctx context.Context, findingID, runID string) (bool, error) {
	items, err := o.deps.DB.Evidence().ForFinding(ctx, findingID)
	if err != nil {
		return false, err
	}
	for _, e := range items {
		if e.RunID == runID {
			return true, nil
		}
	}
	return false, nil
}

func evidencePayload(f finding.Finding, snapshotHash string) []byte {
	canonical := struct {
		FindingID    string           `json:"findingId"`
		Fingerprint  string           `json:"fingerprintKey"`
		State        finding.State    `json:"state"`
		Severity     finding.Severity `json:"severity"`
		Confidence   float64          `json:"confidence"`
		Gates        []string         `json:"gates,omitempty"`
		WeaknessType string           `json:"weaknessClass,omitempty"`
		AssetIDs     []string         `json:"assetIds,omitempty"`
		SnapshotHash string           `json:"snapshotHash"`
	}{
		FindingID:    f.ID,
		Fingerprint:  f.FingerprintKey,
		State:        f.State,
		Severity:     f.Severity,
		Confidence:   f.Confidence.Value,
		Gates:        f.Confidence.Gates,
		WeaknessType: f.WeaknessClass,
		AssetIDs:     f.AssetIDs,
		SnapshotHash: snapshotHash,
	}
	data, _ := json.Marshal(canonical)
	return data
}

func mandatoryFor(f finding.Finding) []string {
	return []string{"parse", "ownership"}
}

func mergeGates(existing, added []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range existing {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, g := range added {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func severityWeight(s finding.Severity) int {
	switch s {
	case finding.SevCritical:
		return 5
	case finding.SevHigh:
		return 4
	case finding.SevMedium:
		return 3
	case finding.SevLow:
		return 2
	case finding.SevInfo:
		return 1
	}
	return 0
}
