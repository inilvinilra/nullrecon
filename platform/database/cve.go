package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/nullrecon/nullrecon/domain/cve"
)

type CVEKnowledge struct {
	db *DB
}

func (d *DB) CVEKnowledge() *CVEKnowledge {
	return &CVEKnowledge{db: d}
}

func (r *CVEKnowledge) Upsert(ctx context.Context, rec cve.Record) error {
	if existing, ok, err := r.Get(ctx, rec.CVE); err != nil {
		return err
	} else if ok {
		rec = cve.Merge(existing, rec)
	}
	data, err := marshal(rec)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	kev := 0
	if rec.KEV {
		kev = 1
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO cveknowledge(cve, cvss_score, cvss_vector, severity, epss, kev, kev_due_date, source, published, last_modified, data, updated_at) "+
			"VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "+
			"ON CONFLICT(cve) DO UPDATE SET cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector, severity=excluded.severity, epss=excluded.epss, kev=excluded.kev, kev_due_date=excluded.kev_due_date, source=excluded.source, published=excluded.published, last_modified=excluded.last_modified, data=excluded.data, updated_at=excluded.updated_at",
		rec.CVE, rec.CVSSScore, rec.CVSSVector, rec.Severity, rec.EPSS, kev, rec.KEVDueDate, rec.Source, rec.Published, rec.LastModified, data, timeString(rec.UpdatedAt)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cveproduct WHERE cve = ?", rec.CVE); err != nil {
		return err
	}
	for _, p := range rec.Products {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO cveproduct(cve, vendor, product, range_start_incl, range_start_excl, range_end_incl, range_end_excl, exact_version) VALUES (?,?,?,?,?,?,?,?)",
			rec.CVE, p.Vendor, p.Product, p.RangeStartIncl, p.RangeStartExcl, p.RangeEndIncl, p.RangeEndExcl, p.ExactVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *CVEKnowledge) Get(ctx context.Context, id string) (cve.Record, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx, "SELECT data FROM cveknowledge WHERE cve = ?", strings.ToUpper(id)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return cve.Record{}, false, nil
	}
	if err != nil {
		return cve.Record{}, false, err
	}
	var rec cve.Record
	if err := unmarshal(data, &rec); err != nil {
		return cve.Record{}, false, err
	}
	return rec, true, nil
}

func (r *CVEKnowledge) ForProduct(ctx context.Context, product string) ([]cve.Record, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT DISTINCT k.data FROM cveknowledge k JOIN cveproduct p ON p.cve = k.cve WHERE p.product = ?",
		strings.ToLower(strings.TrimSpace(product)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cve.Record
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var rec cve.Record
		if err := unmarshal(data, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *CVEKnowledge) Stats(ctx context.Context) (map[string]int, error) {
	stats := map[string]int{}
	var total, kev int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM cveknowledge").Scan(&total); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM cveknowledge WHERE kev = 1").Scan(&kev); err != nil {
		return nil, err
	}
	stats["total"] = total
	stats["kev"] = kev
	var products int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM cveproduct").Scan(&products); err != nil {
		return nil, err
	}
	stats["productRanges"] = products
	return stats, nil
}
