# nullrecon

nullrecon is an open-source, cross-platform, single-binary security platform for
reconnaissance, attack-surface management, exposure detection, active vulnerability
verification, leak intelligence, and evidence collection.

One product, one CLI, one API, one normalized data model, one reporting system. Every
capability sits behind a stable, versioned contract, and every detection engine is
first-party Go. External intelligence APIs are an optional enrichment layer, never a
requirement — the native engines stand alone.

## Highlights

- **Native detection, no wrapped tools.** Subdomain, port/service, fingerprint, content
  discovery, template/exposure, secret, TLS, DNS, service-exposure, and SQL-injection
  engines are all written from scratch in Go — no shelling out to nmap, nuclei, or
  subfinder.
- **2,700+ detection templates** (2,600+ CVE-anchored), including single-request,
  raw-request, reflection, DSL-matcher, multi-request-chained, and out-of-band (OOB)
  classes.
- **Active verification, not just signatures.** SQL injection is confirmed by behaviour
  (boolean differential, error, and optional time-based proof); service exposure is
  confirmed by retrieving real data; blind bugs are confirmed by an OOB callback.
- **False-positive discipline.** Every content matcher passes an adversarial soft-404
  regression gate, and a structural confidence model keeps a passive signal from ever
  reaching the `confirmed` state on its own.
- **Authorization-first.** No scan ever expands beyond its compiled scope; the engine
  fails closed when authorization is ambiguous and never logs secrets.

## Capabilities

| Capability | Engine | Native | Competes with |
| --- | --- | --- | --- |
| Passive subdomain discovery | `engines/subdomain` (crtsh, certspotter, hackertarget, rapiddns, urlscan + keyed sources) | yes | subfinder, amass |
| Active subdomain brute force | `engines/dnsbrute` | yes | subfinder, amass |
| Port + service fingerprint | `engines/portscan` (SSH/FTP/SMTP/MySQL/Redis/PostgreSQL/HTTP versions) | yes | nmap -sV |
| Web probe / fingerprint | `engines/webprobe`, `engines/fingerprint` | yes | httpx, whatweb |
| TLS/SSL analysis | `engines/tlsscan` | yes | testssl.sh, nuclei ssl |
| DNS audit (AXFR / SPF / DMARC) | `engines/dnsaudit` | yes | dnsrecon |
| Content discovery | `engines/contentdiscovery` | yes | ffuf, gobuster |
| Template / exposure / CVE scan | `engines/template`, `engines/exposure` | yes | nuclei |
| Out-of-band (blind) verification | `engines/oob` | yes | interactsh |
| SQL injection | `engines/sqli` | yes | sqlmap (detection) |
| Service exposure (Redis/ES/Mongo/CouchDB unauth) | `engines/svcaudit` | yes | — |
| Secret / leak detection | `engines/secretscan` (69 detectors) | yes | gitleaks, trufflehog |
| Origin-IP discovery | `engines/originip` | yes | — |
| Subdomain takeover | `engines/takeover` | yes | — |
| Honeypot / deception sensing | `engines/honeysense` | yes | — |
| Vulnerability intelligence | `engines/vulnmatch`, `engines/cvefeed` | version-match native; CVE data via NVD/OSV/KEV/EPSS | — |
| Confidence / false-positive control | `analysis/confidence` | yes | — |

## Detection engines

**Passive subdomain discovery** fans out concurrently across five keyless sources
(certificate transparency via crt.sh and certspotter, passive DNS via hackertarget and
rapiddns, and urlscan) plus any keyed providers you configure (SecurityTrails, VirusTotal,
Shodan, Censys, and more). A global timeout keeps a slow or down source — crt.sh is
frequently overloaded — from stalling the run, and results are merged, scoped, and
deduplicated.

**Template engine** runs the embedded library of 2,700+ templates. It supports:
- single-request GET/POST matching (status, word, regex, header, DSL);
- raw HTTP requests;
- reflection findings verified by a payload-free differential control;
- a recursive-descent DSL matcher evaluator;
- multi-request chains with regex extractors feeding `{{variable}}` substitution and a
  per-chain cookie jar (login → authenticated action);
- out-of-band templates that substitute an `{{interactsh-url}}` callback and confirm blind
  SSRF/RCE/XXE against the built-in OOB interactor.

**SQL injection engine** confirms injection by behaviour. For each parameter it sends an
error probe and boolean pairs (numeric, single-quote, double-quote contexts) and reports
only when a database error appears that the baseline lacked, or when the TRUE payload
tracks the baseline while the FALSE payload diverges. With `--confirm` it adds a
time-based proof (MSSQL `WAITFOR`, MySQL `SLEEP`, Postgres `pg_sleep`) — a controlled,
attacker-specified delay that has essentially no explanation other than the database
executing injected SQL. It confirms once per parameter and stops.

**Service exposure engine** actively proves unauthenticated access rather than inferring
it: Redis (`PING` then `INFO`), Elasticsearch (`/` plus `/_cat/indices`), CouchDB (`/`
plus `/_all_dbs`), and MongoDB (OP_MSG `listDatabases`). Each finding carries
`confirmed=true` and the evidence pulled from the service.

**TLS/SSL engine** probes TLS 1.0–1.3 support and inspects the leaf certificate, flagging
deprecated protocol versions, expired/expiring/not-yet-valid certificates, self-signed
certificates, weak signature algorithms (SHA1/MD5), sub-2048-bit RSA keys, and hostname
mismatches.

**DNS audit engine** implements the DNS wire protocol natively to attempt AXFR zone
transfer against each authoritative nameserver, and checks for missing/permissive SPF and
missing/`p=none` DMARC.

## Verification and confidence

Findings are minimal-by-design: an engine that proves a vulnerability stops rather than
re-firing every remaining payload, and extra corroboration (such as the SQLi time-based
proof) is opt-in. Structural confidence gates apply throughout — a passive signal alone
never reaches `confirmed`, and a version-inferred match is confirmed only by active
corroboration. Every content matcher in the template library is covered by an adversarial
soft-404 false-positive regression test.

## CLI

```
# workspace setup
nullrecon init
nullrecon project create --name NAME --slug SLUG
nullrecon project authorize --project SLUG --modes authorizedtest --source S --reference R --days N
nullrecon scope import --project SLUG --label L --file scope.json

# reconnaissance
nullrecon subdomain DOMAIN --passive-only --project SLUG --label L --mode authorizedtest
nullrecon subdomain DOMAIN --project SLUG --label L --mode authorizedtest        # passive + active brute
nullrecon portscan HOST --project SLUG --label L --mode safeactive --top-ports 200
nullrecon tech URL --project SLUG --label L --mode safeactive                    # fingerprint + CVE match
nullrecon origin --domain DOMAIN --project SLUG --label L --mode safeactive      # CDN + DNS origin leaks
nullrecon discover URL --project SLUG --label L --mode authorizedtest --words-file W

# protocol and exposure audits
nullrecon tls HOST:443 --project SLUG --label L --mode authorizedtest
nullrecon dns DOMAIN --project SLUG --label L --mode authorizedtest              # AXFR + SPF/DMARC
nullrecon template scan URL --project SLUG --label L --mode authorizedtest [--oob]
nullrecon exposure --project SLUG --label L --mode authorizedtest --url URL

# active verification
nullrecon sqli --url "URL?id=1" --confirm --project SLUG --label L --mode authorizedtest
nullrecon svc --host HOST --port 9200 --project SLUG --label L --mode authorizedtest

# reporting and intelligence
nullrecon audit --host HOST --port 443 --domain DOMAIN --format markdown --project SLUG --label L --mode authorizedtest
nullrecon cve import --feed        # bulk-load the full ~358k-CVE corpus, no rate limits
nullrecon cve sync --kev ; nullrecon cve stats ; nullrecon cve match --product P --version V
nullrecon workflow run baseline --project SLUG --label L --mode authorizedtest
nullrecon report build --project SLUG --format markdown|sarif|json
nullrecon apikey create --name N --role viewer ; nullrecon serve --addr 127.0.0.1:8787
```

One `workflow run` chains discovery through correlation: passive plus active subdomain
discovery, port and service scanning, technology fingerprinting, content discovery,
exposure/secret/template detection, and CVE correlation against the local store — every
finding gated by the confidence model, every content matcher covered by a false-positive
regression gate.

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
| `analysis` | normalize, correlate, deduplicate, verify, confidence, prioritize, ownership, diff |
| `platform` | database, objectstore, secretvault, auditlog, telemetry, config, runtime |
| `reporting` | renderer, audit report, templates, export, redaction |
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

The `deploy/checks` gate enforces the source conventions (no comments in production Go, no
underscores in package or file names except `_test.go`, gofmt) that keep the tree
consistent.

## Safety baseline

nullrecon is built for authorized security testing. It never expands a target beyond its
compiled authorization scope, fails closed when authorization is ambiguous, and never logs
secrets. Active verification is a first-class capability, but it is minimal by design —
proof once, then stop — and is meant to be run only against systems you are authorized to
test. See `SECURITY.md` and `docs/policy.md`.

## License

AGPL-3.0-or-later. See `LICENSE`.
