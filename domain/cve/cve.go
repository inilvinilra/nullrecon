package cve

import "time"

type Affected struct {
	Vendor         string `json:"vendor"`
	Product        string `json:"product"`
	RangeStartIncl string `json:"rangeStartIncl,omitempty"`
	RangeStartExcl string `json:"rangeStartExcl,omitempty"`
	RangeEndIncl   string `json:"rangeEndIncl,omitempty"`
	RangeEndExcl   string `json:"rangeEndExcl,omitempty"`
	ExactVersion   string `json:"exactVersion,omitempty"`
}

type Record struct {
	CVE          string     `json:"cve"`
	CVSSScore    float64    `json:"cvssScore"`
	CVSSVector   string     `json:"cvssVector,omitempty"`
	Severity     string     `json:"severity,omitempty"`
	EPSS         float64    `json:"epss,omitempty"`
	KEV          bool       `json:"kev"`
	KEVDueDate   string     `json:"kevDueDate,omitempty"`
	Description  string     `json:"description,omitempty"`
	Source       string     `json:"source"`
	Published    string     `json:"published,omitempty"`
	LastModified string     `json:"lastModified,omitempty"`
	Products     []Affected `json:"products,omitempty"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

func (a Affected) HasRange() bool {
	return a.RangeStartIncl != "" || a.RangeStartExcl != "" || a.RangeEndIncl != "" || a.RangeEndExcl != "" || a.ExactVersion != ""
}

func Merge(existing, incoming Record) Record {
	result := incoming
	if result.CVSSScore == 0 && existing.CVSSScore > 0 {
		result.CVSSScore = existing.CVSSScore
		result.CVSSVector = existing.CVSSVector
		result.Severity = existing.Severity
	}
	if result.EPSS == 0 && existing.EPSS > 0 {
		result.EPSS = existing.EPSS
	}
	if existing.KEV {
		result.KEV = true
		if result.KEVDueDate == "" {
			result.KEVDueDate = existing.KEVDueDate
		}
	}
	if result.Description == "" {
		result.Description = existing.Description
	}
	if result.Published == "" {
		result.Published = existing.Published
	}
	if result.LastModified == "" {
		result.LastModified = existing.LastModified
	}
	if len(result.Products) == 0 {
		result.Products = existing.Products
	}
	if existing.Source != "" && incoming.Source != "" && existing.Source != incoming.Source && !hasSource(result.Source, existing.Source) {
		result.Source = incoming.Source + "+" + existing.Source
	}
	return result
}

func hasSource(sources, want string) bool {
	for _, s := range splitSources(sources) {
		if s == want {
			return true
		}
	}
	return false
}

func splitSources(sources string) []string {
	var out []string
	cur := ""
	for _, r := range sources {
		if r == '+' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
