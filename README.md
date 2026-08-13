# nullrecon

nullrecon is an open-source, cross-platform, modular security reconnaissance, attack-surface
management, exposure detection, vulnerability correlation, leak intelligence, and evidence
platform.

One product, one CLI, one API, one normalized data model, one reporting system. Every
capability is isolated behind stable, versioned contracts.

## Status

Working core with native, API-free detection engines and an optional provider layer.
See `docs/adr` for architecture decisions and `docs/roadmap.md` for the delivery phase plan.

## Capabilities

All detection is first-party Go. External APIs are an optional enrichment layer, never a
requirement — the native engines are designed to stand alone.

| Capability | Engine | Native (no API) | Competes with |
| --- | --- | --- | --- |
| Subdomain discovery | `engines/dnsbrute` | yes | subfinder |
| Port and service scan | `engines/portscan` | yes | nmap |
| Web probe / TLS / fingerprint | `engines/webprobe`, `engines/fingerprint` | yes | httpx, whatweb |
| Content discovery | `engines/contentdiscovery` | yes | ffuf, gobuster |
| Template / exposure scan | `engines/template`, `engines/exposure` | yes | nuclei |
| Secret / leak detection | `engines/secretscan` | yes | gitleaks, trufflehog |
| Origin-IP discovery | `engines/originip` | yes | — |
| Honeypot / deception sensing | `engines/honeysense` | yes | — |
| Vulnerability intelligence | `engines/vulnmatch`, `engines/cvefeed` | version match native; CVE data via NVD/OSV/KEV/EPSS | — |
| Confidence / false-positive control | `analysis/confidence` | yes | — |

Every finding passes structural confidence gates: a passive signal alone can never reach the
`confirmed` state; a version-inferred match is only confirmed by active corroboration.

### CLI

```
nullrecon subdomain DOMAIN --project SLUG --label L --mode safeactive
nullrecon portscan HOST --project SLUG --label L --mode safeactive --ports 80,443
nullrecon discover URL --project SLUG --label L --mode authorizedtest --words-file W
nullrecon template scan URL --project SLUG --label L --mode authorizedtest
nullrecon exposure --project SLUG --label L --mode authorizedtest --url URL
nullrecon cve sync (--kev | --since DATE [--until DATE]) ; nullrecon cve stats
nullrecon service list ; nullrecon template list ; nullrecon vuln list --project SLUG
nullrecon workflow run baseline --project SLUG --label L --mode authorizedtest
nullrecon report build --project SLUG --format markdown
nullrecon apikey create --name N --role viewer ; nullrecon serve --addr 127.0.0.1:8787
```

## Layout

| Path | Responsibility |
| --- | --- |
| `apps/cli` | `nullrecon` command line interface |
| `apps/api` | versioned REST API server |
| `apps/worker` | background job workers |
| `apps/web` | optional React/TypeScript interface |
| `core` | orchestrator, workflow, scheduler, policy, scopeguard, budgetguard, eventbus, health |
| `domain` | normalized asset, service, endpoint, technology, exposure, finding, evidence, identity, vulnerability, scanrun models |
| `engines` | first-party scan and analysis engines |
| `providers` | third-party intelligence provider adapters and registry |
| `tools` | isolated external tool runners and parsers |
| `analysis` | normalize, correlate, deduplicate, verify, confidence, prioritize, ownership, diff |
| `platform` | database, objectstore, secretvault, auditlog, telemetry, config, runtime |
| `reporting` | renderer, templates, export, redaction |
| `contracts` | versioned shared contracts |
| `migrations` | database migrations |
| `rules` | versioned rule sets |
| `testdata` | sanitized fixtures |
| `docs` | architecture, ADRs, operational guidance |
| `deploy` | CI enforcement checks and deployment assets |

## Build and test

```
make ci
```

or directly, cross-platform:

```
go run ./deploy/checks -root .
go vet ./...
go test ./...
go build ./...
```

## Safety baseline

nullrecon never expands a target beyond its compiled authorization scope, fails closed when
authorization is ambiguous, and never logs secrets. See `SECURITY.md` and `docs/policy.md`.

## License

AGPL-3.0-or-later. See `LICENSE`.
