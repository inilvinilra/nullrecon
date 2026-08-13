package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/exposure"
	"github.com/nullrecon/nullrecon/domain/finding"
	"github.com/nullrecon/nullrecon/domain/vulnerability"
)

type Exposures struct {
	db *DB
}

func (d *DB) Exposures() *Exposures {
	return &Exposures{db: d}
}

func (r *Exposures) Put(ctx context.Context, e exposure.Exposure) error {
	if e.ID == "" {
		e.ID = contracts.NewID("exp")
	}
	if e.Version == "" {
		e.Versioned = contracts.NewVersioned("exposure")
	}
	data, err := marshal(e)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO exposures(id, project_id, asset_id, category, data, observed_at) VALUES (?,?,?,?,?,?)",
		e.ID, e.ProjectID, e.AssetID, string(e.Category), data, timeString(e.ObservedAt))
	return err
}

func (r *Exposures) ForProject(ctx context.Context, projectID string) ([]exposure.Exposure, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM exposures WHERE project_id = ? ORDER BY observed_at", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.Exposure
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e exposure.Exposure
		if err := unmarshal(data, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type SecretCandidates struct {
	db *DB
}

func (d *DB) SecretCandidates() *SecretCandidates {
	return &SecretCandidates{db: d}
}

func (r *SecretCandidates) Upsert(ctx context.Context, s exposure.SecretCandidate) error {
	if s.ID == "" {
		s.ID = contracts.NewID("sec")
	}
	if s.Version == "" {
		s.Versioned = contracts.NewVersioned("secretcandidate")
	}
	data, err := marshal(s)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO secretcandidates(id, project_id, asset_id, detector, fingerprint, preview, location, validation, data, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(project_id, detector, fingerprint, location) DO UPDATE SET validation=excluded.validation, last_seen=excluded.last_seen, data=excluded.data",
		s.ID, s.ProjectID, s.AssetID, s.Detector, s.Fingerprint, s.Preview, s.Location, string(s.Validation), data, timeString(s.FirstSeen), timeString(s.LastSeen))
	return err
}

func (r *SecretCandidates) ByFingerprint(ctx context.Context, projectID, detector, fingerprint, location string) (exposure.SecretCandidate, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx,
		"SELECT data FROM secretcandidates WHERE project_id = ? AND detector = ? AND fingerprint = ? AND location = ?",
		projectID, detector, fingerprint, location).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return exposure.SecretCandidate{}, false, nil
	}
	if err != nil {
		return exposure.SecretCandidate{}, false, err
	}
	var s exposure.SecretCandidate
	if err := unmarshal(data, &s); err != nil {
		return exposure.SecretCandidate{}, false, err
	}
	return s, true, nil
}

func (r *SecretCandidates) ForProject(ctx context.Context, projectID string) ([]exposure.SecretCandidate, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM secretcandidates WHERE project_id = ? ORDER BY last_seen DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.SecretCandidate
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var s exposure.SecretCandidate
		if err := unmarshal(data, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

type VulnCandidates struct {
	db *DB
}

func (d *DB) VulnCandidates() *VulnCandidates {
	return &VulnCandidates{db: d}
}

func (r *VulnCandidates) Upsert(ctx context.Context, c vulnerability.Candidate) error {
	if c.ID == "" {
		c.ID = contracts.NewID("vul")
	}
	if c.Version == "" {
		c.Versioned = contracts.NewVersioned("vulnerabilitycandidate")
	}
	data, err := marshal(c)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO vulnerabilitycandidates(id, project_id, asset_id, cve, ghsa, matched_by, state, data, observed_at) VALUES (?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(asset_id, cve, matched_by) DO UPDATE SET state=excluded.state, data=excluded.data, observed_at=excluded.observed_at",
		c.ID, c.ProjectID, c.AssetID, c.CVE, c.GHSA, string(c.MatchedBy), string(c.State), data, timeString(c.ObservedAt))
	return err
}

func (r *VulnCandidates) ByKey(ctx context.Context, assetID, cve string, matchedBy vulnerability.MatchedBy) (vulnerability.Candidate, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx,
		"SELECT data FROM vulnerabilitycandidates WHERE asset_id = ? AND cve = ? AND matched_by = ?",
		assetID, cve, string(matchedBy)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return vulnerability.Candidate{}, false, nil
	}
	if err != nil {
		return vulnerability.Candidate{}, false, err
	}
	var c vulnerability.Candidate
	if err := unmarshal(data, &c); err != nil {
		return vulnerability.Candidate{}, false, err
	}
	return c, true, nil
}

func (r *VulnCandidates) ForProject(ctx context.Context, projectID string) ([]vulnerability.Candidate, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM vulnerabilitycandidates WHERE project_id = ? ORDER BY observed_at DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vulnerability.Candidate
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c vulnerability.Candidate
		if err := unmarshal(data, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type Findings struct {
	db *DB
}

func (d *DB) Findings() *Findings {
	return &Findings{db: d}
}

func (r *Findings) ByFingerprint(ctx context.Context, projectID, key string) (finding.Finding, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM findings WHERE project_id = ? AND fingerprint_key = ?", projectID, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return finding.Finding{}, false, nil
	}
	if err != nil {
		return finding.Finding{}, false, err
	}
	var f finding.Finding
	if err := unmarshal(data, &f); err != nil {
		return finding.Finding{}, false, err
	}
	return f, true, nil
}

func (r *Findings) Upsert(ctx context.Context, f finding.Finding) error {
	if f.ID == "" {
		f.ID = contracts.NewID("fnd")
	}
	if f.Version == "" {
		f.Versioned = contracts.NewVersioned("finding")
	}
	data, err := marshal(f)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO findings(id, project_id, title, state, severity, fingerprint_key, snapshot_hash, first_seen, last_seen, data) VALUES (?,?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(project_id, fingerprint_key) DO UPDATE SET title=excluded.title, state=excluded.state, severity=excluded.severity, snapshot_hash=excluded.snapshot_hash, last_seen=excluded.last_seen, data=excluded.data",
		f.ID, f.ProjectID, f.Title, string(f.State), string(f.Severity), f.FingerprintKey, f.SnapshotHash, timeString(f.FirstSeen), timeString(f.LastSeen), data)
	return err
}

func (r *Findings) List(ctx context.Context, projectID string) ([]finding.Finding, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM findings WHERE project_id = ? ORDER BY last_seen DESC", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finding.Finding
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var f finding.Finding
		if err := unmarshal(data, &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *Findings) Get(ctx context.Context, id string) (finding.Finding, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM findings WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return finding.Finding{}, errors.New("database: finding not found")
	}
	if err != nil {
		return finding.Finding{}, err
	}
	var f finding.Finding
	if err := unmarshal(data, &f); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}

func (r *Findings) Relate(ctx context.Context, rel finding.Relation) error {
	if rel.ID == "" {
		rel.ID = contracts.NewID("frel")
	}
	if rel.Version == "" {
		rel.Versioned = contracts.NewVersioned("findingrelation")
	}
	data, err := marshal(rel)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO findingrelations(id, project_id, from_id, to_id, kind, data, created_at) VALUES (?,?,?,?,?,?,?) "+
			"ON CONFLICT(from_id, to_id, kind) DO NOTHING",
		rel.ID, rel.ProjectID, rel.FromID, rel.ToID, string(rel.Kind), data, timeString(rel.CreatedAt))
	return err
}

func (r *Findings) Relations(ctx context.Context, findingID string) ([]finding.Relation, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT data FROM findingrelations WHERE from_id = ? OR to_id = ?", findingID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finding.Relation
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var rel finding.Relation
		if err := unmarshal(data, &rel); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}
