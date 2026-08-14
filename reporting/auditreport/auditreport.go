package auditreport

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	Confirmed   bool   `json:"confirmed"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type Report struct {
	Title       string    `json:"title"`
	GeneratedAt time.Time `json:"generatedAt"`
	Scope       []string  `json:"scope,omitempty"`
	Findings    []Finding `json:"findings"`
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func remediationFor(id string) string {
	switch id {
	case "redis-unauthenticated-access":
		return "Enable `requirepass`/ACLs, bind to localhost or a private interface, and enable protected-mode."
	case "elasticsearch-unauthenticated-access":
		return "Enable the security plugin (xpack.security.enabled), require authentication, and firewall port 9200."
	case "couchdb-unauthenticated-access":
		return "Set an admin password (disable admin-party), require auth, and restrict network access."
	case "mongodb-unauthenticated-access":
		return "Enable authorization (--auth), create an admin user, and bind to a private interface."
	case "dns-zone-transfer":
		return "Restrict AXFR to authorized secondary nameservers only (allow-transfer)."
	case "certificate-expired", "certificate-expiring":
		return "Renew and deploy a valid certificate; automate renewal (ACME)."
	case "self-signed-certificate":
		return "Replace with a certificate from a trusted CA."
	case "tls-version-1.0", "tls-version-1.1":
		return "Disable TLS 1.0/1.1; require TLS 1.2 or higher."
	case "weak-signature-algorithm", "weak-rsa-key":
		return "Reissue the certificate with SHA-256+ and a 2048-bit or stronger key."
	case "spf-missing", "spf-permissive":
		return "Publish a strict SPF record (end with -all)."
	case "dmarc-missing", "dmarc-policy-none":
		return "Publish a DMARC record with an enforced policy (p=quarantine or p=reject)."
	}
	return ""
}

func (r Report) normalize() []Finding {
	out := make([]Finding, len(r.Findings))
	copy(out, r.Findings)
	for i := range out {
		if out[i].Remediation == "" {
			out[i].Remediation = remediationFor(out[i].ID)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func (r Report) Counts() map[string]int {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

func Markdown(r Report) string {
	findings := r.normalize()
	var b strings.Builder
	title := r.Title
	if title == "" {
		title = "Security Audit Report"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "_Generated: %s UTC_\n\n", r.GeneratedAt.UTC().Format("2006-01-02 15:04"))
	if len(r.Scope) > 0 {
		fmt.Fprintf(&b, "**Scope:** %s\n\n", strings.Join(r.Scope, ", "))
	}

	counts := r.Counts()
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", sev, counts[sev])
		}
	}
	confirmed := 0
	for _, f := range findings {
		if f.Confirmed {
			confirmed++
		}
	}
	fmt.Fprintf(&b, "\n**Total findings:** %d (%d actively confirmed)\n\n", len(findings), confirmed)

	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	for i, f := range findings {
		status := "unconfirmed"
		if f.Confirmed {
			status = "CONFIRMED"
		}
		fmt.Fprintf(&b, "### %d. %s\n\n", i+1, titleOf(f))
		fmt.Fprintf(&b, "- **Severity:** %s\n", strings.ToUpper(f.Severity))
		fmt.Fprintf(&b, "- **Status:** %s\n", status)
		fmt.Fprintf(&b, "- **Target:** %s\n", f.Target)
		if f.Detail != "" {
			fmt.Fprintf(&b, "- **Detail:** %s\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:** `%s`\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "- **Remediation:** %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func titleOf(f Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return f.ID
}
