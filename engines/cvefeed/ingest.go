package cvefeed

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/domain/cve"
	"github.com/nullrecon/nullrecon/providers/registry"
)

type cpeRange struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type Ingestor struct {
	now func() time.Time
}

func NewIngestor() *Ingestor {
	return &Ingestor{now: func() time.Time { return time.Now().UTC() }}
}

func (in *Ingestor) Merge(records []registry.Record) []cve.Record {
	byCVE := map[string]*cve.Record{}
	order := []string{}
	get := func(id string) *cve.Record {
		if r, ok := byCVE[id]; ok {
			return r
		}
		r := &cve.Record{CVE: id, UpdatedAt: in.now()}
		byCVE[id] = r
		order = append(order, id)
		return r
	}
	for _, rec := range records {
		id := strings.ToUpper(strings.TrimSpace(rec.Value))
		if id == "" {
			continue
		}
		switch rec.Kind {
		case "cve":
			if rec.Fields["status"] == "Rejected" {
				continue
			}
			r := get(id)
			applyNVD(r, rec)
		case "kev":
			r := get(id)
			r.KEV = true
			if due := rec.Fields["dueDate"]; due != "" {
				r.KEVDueDate = due
			}
			if r.Source == "" {
				r.Source = "cisa-kev"
			}
		case "epss":
			r := get(id)
			if v, err := strconv.ParseFloat(rec.Fields["epss"], 64); err == nil {
				r.EPSS = v
			}
			if r.Source == "" {
				r.Source = "epss"
			}
		}
	}
	out := make([]cve.Record, 0, len(order))
	for _, id := range order {
		out = append(out, *byCVE[id])
	}
	return out
}

func applyNVD(r *cve.Record, rec registry.Record) {
	r.Source = "nvd"
	if v, err := strconv.ParseFloat(rec.Fields["cvssScore"], 64); err == nil {
		r.CVSSScore = v
	}
	if vec := rec.Fields["cvssVector"]; vec != "" {
		r.CVSSVector = vec
	}
	if sev := rec.Fields["severity"]; sev != "" {
		r.Severity = sev
	}
	if desc := rec.Fields["description"]; desc != "" {
		r.Description = desc
	}
	if pub := rec.Fields["published"]; pub != "" {
		r.Published = pub
	}
	if mod := rec.Fields["lastModified"]; mod != "" {
		r.LastModified = mod
	}
	r.Products = affectedFromRanges(rec.Fields["cpeRanges"])
}

func affectedFromRanges(encoded string) []cve.Affected {
	if encoded == "" {
		return nil
	}
	var ranges []cpeRange
	if err := json.Unmarshal([]byte(encoded), &ranges); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []cve.Affected
	for _, rng := range ranges {
		if !rng.Vulnerable {
			continue
		}
		vendor, product, ok := parseCPE(rng.Criteria)
		if !ok {
			continue
		}
		aff := cve.Affected{
			Vendor:         vendor,
			Product:        product,
			RangeStartIncl: rng.VersionStartIncluding,
			RangeStartExcl: rng.VersionStartExcluding,
			RangeEndIncl:   rng.VersionEndIncluding,
			RangeEndExcl:   rng.VersionEndExcluding,
		}
		if !aff.HasRange() {
			exact := exactVersionFromCPE(rng.Criteria)
			if exact == "" {
				continue
			}
			aff.ExactVersion = exact
		}
		key := aff.Vendor + "|" + aff.Product + "|" + aff.RangeStartIncl + "|" + aff.RangeStartExcl + "|" + aff.RangeEndIncl + "|" + aff.RangeEndExcl + "|" + aff.ExactVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, aff)
	}
	return out
}

func exactVersionFromCPE(criteria string) string {
	fields := splitCPE(criteria)
	if len(fields) < 6 {
		return ""
	}
	version := unescapeCPE(fields[5])
	if version == "" || version == "*" || version == "-" {
		return ""
	}
	return version
}
