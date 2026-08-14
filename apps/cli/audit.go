package main

import (
	"strconv"
	"time"

	"github.com/nullrecon/nullrecon/engines/dnsaudit"
	"github.com/nullrecon/nullrecon/engines/svcaudit"
	"github.com/nullrecon/nullrecon/engines/tlsscan"
	"github.com/nullrecon/nullrecon/reporting/auditreport"
)

func (c commandContext) cmdAudit(args []string) int {
	host, hasHost := flagValue(args, "--host")
	domain, hasDomain := flagValue(args, "--domain")
	if !hasHost && !hasDomain {
		return c.fail(exitUsage, "audit requires --host (with --port) or --domain")
	}
	ctx, db, snap, _, code := c.prepareRun(args)
	if code != -1 {
		return code
	}
	defer db.Close()

	report := auditreport.Report{Title: "nullrecon Security Audit", GeneratedAt: time.Now().UTC()}

	if hasHost {
		report.Scope = append(report.Scope, host)
		if portStr, ok := flagValue(args, "--port"); ok {
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
				svc := svcaudit.New(snap, budgetFromScope(snap))
				if res, err := svc.Scan(ctx, host, port); err == nil {
					for _, f := range res.Findings {
						report.Findings = append(report.Findings, auditreport.Finding{
							ID: f.ID, Severity: f.Severity, Target: host + ":" + portStr,
							Confirmed: f.Confirmed, Detail: f.Detail, Evidence: f.Evidence,
						})
					}
				}
				if port == 443 || port == 8443 || flagPresent(args, "--tls") {
					tlsEng := tlsscan.New(snap, budgetFromScope(snap))
					if res, err := tlsEng.Scan(ctx, host+":"+portStr); err == nil {
						for _, f := range res.Findings {
							report.Findings = append(report.Findings, auditreport.Finding{
								ID: f.ID, Severity: f.Severity, Target: host + ":" + portStr,
								Confirmed: true, Detail: f.Detail,
							})
						}
					}
				}
			}
		}
	}

	if hasDomain {
		report.Scope = append(report.Scope, domain)
		dns := dnsaudit.New(snap, budgetFromScope(snap))
		if res, err := dns.Scan(ctx, domain); err == nil {
			for _, f := range res.Findings {
				report.Findings = append(report.Findings, auditreport.Finding{
					ID: f.ID, Severity: f.Severity, Target: domain,
					Confirmed: f.ID == "dns-zone-transfer", Detail: f.Detail,
				})
			}
		}
	}

	if format, _ := flagValue(args, "--format"); format == "markdown" {
		c.stdout.Write([]byte(auditreport.Markdown(report)))
		return 0
	}
	return c.emit(report)
}
