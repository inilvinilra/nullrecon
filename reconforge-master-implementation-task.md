# ReconForge Master Implementation Task

## 1. Mission

Build ReconForge as an open-source, cross-platform, modular security reconnaissance, attack-surface management, exposure detection, vulnerability correlation, leak intelligence, and evidence platform.

ReconForge must present one product, one CLI, one API, one normalized data model, and one reporting system while keeping every capability isolated behind stable contracts.

The product must coordinate passive intelligence, authorized active discovery, service fingerprinting, port scanning, content discovery, vulnerability checks, honeypot analysis, CVE enrichment, leak detection, secret detection, false-positive suppression, evidence preservation, and reporting from one workflow.

The product must not become a thin command wrapper. Its primary intellectual property must be the orchestration engine, scope compiler, provider abstraction, normalized asset graph, correlation system, verification pipeline, confidence model, evidence chain, and reproducible workflow engine.

## 2. Non-Negotiable Engineering Rules

1. Use a single monorepo.
2. Use Go for the core, CLI, API, workers, provider adapters, parsers, correlation logic, and orchestration engine.
3. Use React and TypeScript for the optional web interface after the CLI and API are stable.
4. Support Linux, macOS, and Windows.
5. Do not assume POSIX-only paths, shells, signals, permissions, package managers, or process behavior.
6. Production source code must contain no comments or comment-only lines.
7. Architecture explanations, rationale, protocol notes, operational warnings, and maintenance guidance belong in `docs`.
8. Project-controlled module, package, and directory names must not contain underscores.
9. Use clear lower-case names for Go packages and directories.
10. Follow language-required filename conventions. Go test files may use the required `_test.go` suffix.
11. Do not create one generic `utils`, `helpers`, `common`, `misc`, or `manager` package.
12. Every package must have one explicit responsibility and a narrow public API.
13. Do not let provider-specific response structures escape provider adapters.
14. Do not let external scanner output escape tool parsers.
15. Store raw source artifacts and normalized records separately.
16. All persisted schemas, events, provider contracts, and rule formats must be versioned.
17. Every mutation must be idempotent or protected by an idempotency key.
18. Every long-running job must support cancellation, retry, timeout, checkpoint, and resumability.
19. No API key, token, cookie, signed URL, credential, raw secret, or sensitive response body may appear in logs.
20. Never silently expand a target beyond its compiled authorization scope.
21. Passive discovery is not permission for active testing.
22. A vulnerability disclosure page or reporting email is not proof of authorization.
23. Destructive testing, denial of service, persistence, credential abuse, data modification, and uncontrolled exploitation are outside the product baseline.
24. Proof-of-concept verification must be non-destructive, minimal, reproducible, and explicitly authorized by policy.
25. The system must fail closed when authorization, target ownership, provider capability, or action safety is ambiguous.

## 3. Product Operating Modes

Implement four modes and enforce them in the policy engine.

### Passive

Use cached or third-party public datasets without sending traffic to the target from ReconForge.

Allowed examples:

- Internet asset search
- Certificate intelligence
- Passive DNS
- Previously captured URL intelligence
- Public vulnerability intelligence
- Public repository exposure analysis
- Previously indexed LeakIX data

### SafeActive

Send low-impact requests to explicitly authorized targets.

Allowed examples:

- DNS resolution
- TCP connect checks
- HTTP HEAD or bounded GET requests
- TLS handshake inspection
- Conservative service probing
- Low-rate technology fingerprinting

### AuthorizedTest

Run explicit, scope-approved security checks with limits defined by the program policy.

Allowed examples:

- Nuclei templates allowed by risk category
- ffuf discovery with approved dictionaries and rate budgets
- Nmap service discovery and approved NSE categories
- Non-destructive vulnerability verification
- Read-only credential or secret validation when ownership and authorization are proven

### WatchOnly

Store and enrich assets but never send active traffic or validate credentials.

Use this mode for watchlists, report-only programs, targets with unclear authorization, and high-risk infrastructure.

## 4. Scope and Authorization Model

Create a machine-enforced scope system before implementing active scanners.

Each project must define:

- Project identity
- Authorization source
- Authorization start and end dates
- Allowed root domains
- Allowed exact domains
- Allowed IPs and CIDR ranges
- Allowed URLs and path prefixes
- Allowed ports and protocols
- Allowed test accounts
- Allowed scan classes
- Allowed verification classes
- Denied assets
- Denied paths
- Denied actions
- Rate limits
- Concurrency limits
- Request budgets
- Time windows
- Data retention rules
- Evidence redaction rules
- Emergency stop conditions

Compile the input policy into an immutable `ScopeSnapshot` for each scan run. Store its hash with every job and finding.

Classify assets as:

- `active`
- `reportonly`
- `watchonly`
- `denied`
- `unknown`

Only `active` assets may enter active workflows. Any redirect, CNAME, resolved IP, alternate hostname, discovered URL, or provider pivot must pass scope evaluation again before use.

## 5. Monorepo Architecture

Use this baseline and refine it only when a concrete dependency boundary requires a change.

```text
reconforge/
├── apps/
│   ├── cli/
│   ├── api/
│   ├── worker/
│   └── web/
├── core/
│   ├── orchestrator/
│   ├── workflow/
│   ├── scheduler/
│   ├── policy/
│   ├── scopeguard/
│   ├── budgetguard/
│   ├── eventbus/
│   └── health/
├── domain/
│   ├── asset/
│   ├── service/
│   ├── endpoint/
│   ├── technology/
│   ├── exposure/
│   ├── finding/
│   ├── evidence/
│   ├── identity/
│   ├── vulnerability/
│   └── scanrun/
├── engines/
│   ├── portscan/
│   ├── webprobe/
│   ├── dnscan/
│   ├── fingerprint/
│   ├── contentdiscovery/
│   ├── vulnscan/
│   ├── honeysense/
│   ├── leakintel/
│   ├── secretscan/
│   └── takeover/
├── providers/
│   ├── registry/
│   ├── fofa/
│   ├── censys/
│   ├── netlas/
│   ├── shodan/
│   ├── leakix/
│   ├── greynoise/
│   ├── urlscan/
│   ├── securitytrails/
│   ├── github/
│   ├── gitlab/
│   ├── hibp/
│   ├── nvd/
│   ├── cisa/
│   ├── epss/
│   └── ghsa/
├── tools/
│   ├── runner/
│   ├── nmap/
│   ├── nuclei/
│   ├── ffuf/
│   ├── gitleaks/
│   └── trufflehog/
├── analysis/
│   ├── normalize/
│   ├── correlate/
│   ├── deduplicate/
│   ├── verify/
│   ├── confidence/
│   ├── prioritize/
│   ├── ownership/
│   └── diff/
├── platform/
│   ├── database/
│   ├── objectstore/
│   ├── secretvault/
│   ├── auditlog/
│   ├── telemetry/
│   ├── config/
│   └── runtime/
├── reporting/
│   ├── renderer/
│   ├── templates/
│   ├── export/
│   └── redaction/
├── contracts/
├── migrations/
├── rules/
├── testdata/
├── docs/
└── deploy/
```

## 6. Core Domain Model

Implement stable identifiers and versioned records for the following entities:

### Project

Owns scope, authorization, credentials, policies, workflows, findings, and retention settings.

### Asset

Represents a domain, hostname, IP, CIDR, URL root, cloud resource, repository, organization, certificate, or autonomous system.

### AssetClaim

Represents a source assertion that an asset belongs to or relates to a project. It must preserve source, observed time, fetched time, raw artifact reference, confidence components, and ownership state.

### Service

Represents a protocol and port observation tied to an asset and observation time.

### Endpoint

Represents a URL, route, method, parameter set, content type, authentication state, and discovery source.

### Technology

Represents a product, vendor, version constraint, CPE candidate, package identity, fingerprint method, and confidence.

### Exposure

Represents an externally visible condition such as an open database, directory listing, public backup, debug endpoint, exposed repository metadata, unsafe administrative interface, or leaked configuration file.

### SecretCandidate

Represents a secret-like value through an irreversible fingerprint, redacted preview, detector identity, source location, context hash, ownership state, and validation state. Never store the raw value in this table.

### VulnerabilityCandidate

Represents a possible CVE or advisory mapping based on product, version, CPE, package, template, or provider intelligence.

### Finding

Represents an analyst-facing conclusion. A finding must reference one or more observations and must not be created directly from an unverified provider record.

### Evidence

Represents reproducible proof with timestamps, hashes, tool version, request metadata, redacted response metadata, source provenance, and storage reference.

### ScanRun

Represents a reproducible execution with policy snapshot, tool versions, rule versions, provider versions, budgets, timestamps, environment metadata, and outcome.

## 7. Provider Abstraction

Do not hard-code workflows around provider names. Define capability contracts and register adapters dynamically.

Initial capabilities:

- `AssetSearch`
- `HostLookup`
- `ServiceSearch`
- `CertificateSearch`
- `DnsCurrent`
- `DnsHistory`
- `DomainLookup`
- `SubdomainSearch`
- `LeakSearch`
- `NoiseLookup`
- `UrlHistory`
- `UrlSubmit`
- `RepoSearch`
- `SecretSignalSearch`
- `BreachDomainLookup`
- `CveLookup`
- `CpeLookup`
- `AdvisoryLookup`
- `ExploitPriorityLookup`
- `UsageLookup`

Each adapter must expose:

- Provider name and adapter version
- Supported capabilities
- Authentication requirements
- Account tier limitations
- Query limits
- Pagination model
- Credit cost estimator
- Rate-limit state
- Retry policy
- Timeout policy
- Freshness metadata
- Field coverage
- Terms and redistribution metadata
- Health status
- Normalization version

Implement the following initial providers:

| Provider | Primary role |
|---|---|
| FOFA | Asset, service, certificate, product and banner intelligence |
| Censys | Host, web property, service and certificate intelligence |
| Netlas | Host, response, DNS, WHOIS, certificate and exposure intelligence |
| Shodan | Host, service, banner, CPE and vulnerability hints |
| LeakIX | Indexed service and public leak signals |
| GreyNoise | Internet scanner, noise and IP context |
| urlscan | Historical URL, page, request, domain, IP and certificate intelligence |
| SecurityTrails | Current and historical DNS and subdomain intelligence |
| GitHub | Repository, code, advisory and organization-scoped exposure signals |
| GitLab | Repository and organization-scoped exposure signals |
| HIBP | Verified-domain breach exposure only |
| NVD | CVE and CPE enrichment |
| CISA | Known Exploited Vulnerabilities enrichment |
| EPSS | Exploitation probability enrichment |
| GHSA | Open-source advisory and affected-package enrichment |

Provider requests must use server-side credentials from `SecretVault`. Implement per-provider credit budgets, cache policy, circuit breakers, concurrency limits, backoff, pagination checkpoints, and cost visibility.

Provider data is an observation, never automatic truth. Preserve `observedAt`, `fetchedAt`, `sourceId`, `sourceUrl` when safe, `rawHash`, `adapterVersion`, and `freshnessClass`.

## 8. External Tool Integration

Integrate external tools through isolated runners and strict parsers.

### Nmap

- Detect system installation and version.
- Do not bundle Nmap or Npcap until licensing has been reviewed and approved.
- Use XML output.
- Support conservative discovery, TCP connect, version detection, and explicitly allowed NSE classes.
- Store the exact command plan separately from redacted user output.
- Parse XML into normalized assets, services, technologies, observations, and evidence.

### Nuclei

- Start with JSONL CLI integration.
- Keep an SDK migration path.
- Pin engine and template revisions for reproducibility.
- Classify templates by protocol, severity, tags, side effects, authentication needs, request count, and safety level.
- Deny unknown, intrusive, fuzzing, headless, code, and destructive templates unless explicitly allowed.
- Do not promote template matches without verification policy evaluation.

### ffuf

- Use JSON or eJSON output.
- Select dictionaries by technology, route type, language, and prior observations.
- Implement calibration, baseline requests, wildcard detection, redirect normalization, soft-404 detection, similarity clustering, and response-size filtering.
- Enforce per-host request and concurrency budgets.

### Gitleaks and TruffleHog

- Use as optional secret detector adapters.
- Accept repositories, commit history, authorized local files, and approved remote sources.
- Preserve detector provenance and rule revision.
- Never print raw detected secrets.
- Do not automatically validate a secret against a provider unless the project policy explicitly permits a read-only verifier for an owned and authorized resource.

## 9. First-Party Engines

Build the following as ReconForge-owned components.

### PortScan

Provide a safe TCP connect engine first. Add SYN and UDP capabilities only behind privilege checks, platform-specific implementations, and explicit policy grants.

### WebProbe

Collect bounded HTTP metadata, redirects, headers, TLS details, content hashes, titles, favicon hashes, selected body features, and response timing.

### DnsScan

Resolve and correlate A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, and PTR observations with explicit query budgets.

### Fingerprint

Combine headers, cookies, HTML markers, scripts, favicon hashes, TLS metadata, protocol behavior, banners, package manifests, and provider signals. Return ranked candidates with component evidence.

### ContentDiscovery

Plan wordlists and filters based on known technology and prior responses. Treat discoveries as endpoints, not vulnerabilities.

### VulnScan

Map services and technologies to relevant checks. Separate candidate generation from verification.

### HoneySense

Produce a probabilistic deception score rather than a binary decision.

Signals must include:

- Implausible port density
- Repeated banners across unrelated ports
- Protocol and banner contradictions
- TLS identity contradictions
- Known honeypot fingerprints
- Uniform response timing
- Synthetic error patterns
- Inconsistent operating-system traits
- Provider disagreement
- Connection behavior anomalies

Store every component score. Never hide the evidence behind one opaque number. A high deception score must reduce scan intensity and request analyst review; it must not silently delete the asset.

### LeakIntel

Unify exposure and leak signals from approved sources without collecting or redistributing illicit datasets.

Supported leak categories:

- Public repository secrets
- Historical commit secrets
- Exposed environment and configuration files
- Public backup and archive files
- Directory listings
- Exposed source maps
- Public object-store misconfiguration signals
- Exposed database or management service signals
- Public debug and diagnostic endpoints
- Leaked keys, tokens, certificates and private-key material
- Verified-domain breach metadata
- Paste or index metadata from approved providers

Every leak signal must carry ownership state, discovery source, source visibility, collection legality classification, sensitivity class, redacted preview, irreversible fingerprint, first-seen time, last-seen time, validation state, and remediation state.

Never store breach dumps, passwords, session cookies, identity documents, unrelated personal data, or full third-party datasets. Store only the minimum evidence required for defensive notification and remediation.

## 10. False-Positive Elimination Pipeline

False-positive reduction is a first-class product capability. Implement a staged pipeline and persist each decision.

### Stage 1: Parse Validity

- Validate source schema.
- Reject truncated or structurally invalid records.
- Record parser errors without losing raw artifacts.
- Normalize encodings, URLs, hostnames, IPs, timestamps, and port values.

### Stage 2: Scope and Ownership

- Confirm the signal maps to an authorized project asset.
- Distinguish exact ownership, inherited ownership, historical relation, shared infrastructure, CDN edge, cloud shared tenancy, and unknown relation.
- Never treat shared IP ownership as domain ownership.
- Never treat certificate co-occurrence as conclusive ownership.

### Stage 3: Freshness

- Evaluate observation age.
- Apply provider-specific freshness decay.
- Mark historical records separately.
- Never report a stale provider record as currently exposed without current evidence.

### Stage 4: Deduplication

- Generate stable fingerprints from normalized asset, service, endpoint, detector, weakness class, and evidence characteristics.
- Merge equivalent records while preserving every source assertion.
- Keep temporal recurrences as a timeline rather than duplicate findings.

### Stage 5: Baseline and Control Requests

- Use negative controls where active policy permits.
- Detect wildcard DNS.
- Detect catch-all virtual hosts.
- Detect soft 404 pages.
- Detect uniform redirect handlers.
- Detect WAF block pages.
- Detect authentication gateways.
- Detect CDN error templates.

### Stage 6: Semantic Verification

- Confirm that evidence matches the claimed weakness.
- Require technology and version compatibility for CVE candidates.
- Parse version ranges instead of using string comparison.
- Distinguish vendor backports and distribution package revisions.
- Require route, protocol, configuration, or feature prerequisites where known.

### Stage 7: Cross-Source Correlation

- Compare passive providers.
- Compare passive data with current active observations when authorized.
- Detect provider copying or shared upstream data to avoid fake independence.
- Weight sources by freshness, directness, coverage, and historical accuracy.

### Stage 8: Safe Verification

- Select a verifier by finding class.
- Enforce read-only and non-destructive behavior.
- Limit retries and requests.
- Capture minimal evidence.
- Stop on unexpected state, sensitive data, instability, or policy breach.

### Stage 9: Confidence Decision

Store component scores:

- Parse confidence
- Ownership confidence
- Freshness confidence
- Fingerprint confidence
- Version confidence
- Prerequisite confidence
- Cross-source confidence
- Active verification confidence
- Deception penalty
- Shared-infrastructure penalty
- WAF or gateway penalty
- Staleness penalty

Do not calculate confidence as a naive average. Use rule-specific gates and weighted models. A missing mandatory prerequisite must cap or reject the finding regardless of other scores.

### Stage 10: Human Review

Route ambiguous, high-impact, sensitive, novel, conflicting, or secret-bearing findings to review. Store reviewer decision, reason code, timestamp, and model or rule revision.

Use these final states:

- `confirmed`
- `likely`
- `potential`
- `informational`
- `falsepositive`
- `stale`
- `duplicate`
- `outofscope`
- `needsreview`

## 11. Secret and Leak Verification Policy

Implement verifier classes with explicit safety contracts.

### Offline Verification

- Format validation
- Checksum validation
- Entropy scoring
- Prefix and provider classification
- Context analysis
- Placeholder and example-key detection
- Test-fixture detection
- Known revocation pattern detection
- Public-key derivation where mathematically safe and relevant

### Online Read-Only Verification

Permit only when all conditions are true:

- The asset owner is verified.
- The target is in `active` scope.
- The authorization explicitly permits credential validation.
- A provider-specific verifier is allowlisted.
- The endpoint is read-only and low impact.
- The verifier cannot enumerate unrelated tenant data.
- The request does not modify state.
- The request budget allows it.
- The raw secret remains inside the isolated verifier process.

If any condition fails, label the candidate `unverified` and do not attempt authentication.

Store full secrets only in encrypted evidence storage when strictly required. The normal database must contain only a keyed fingerprint and redacted preview. Provide audited CLI reveal and export workflows that require explicit authorization.

## 12. Evidence and Secret Vault

Implement encrypted local storage first and optional remote object storage later.

Requirements:

- Envelope encryption
- OS keychain integration where available
- Project-scoped encryption keys
- Separate metadata and secret material
- Content hashes
- Immutable evidence manifests
- Retention policies
- Secure deletion where supported
- Export-time redaction
- Access audit trail
- No secret values in process arguments
- No secret values in environment dumps
- No secret values in crash reports

Required CLI operations:

```text
reconforge finding list
reconforge finding show FINDINGID
reconforge finding verify FINDINGID
reconforge evidence show FINDINGID
reconforge evidence export FINDINGID
reconforge evidence timeline FINDINGID
reconforge secret reveal FINDINGID
reconforge secret export FINDINGID
reconforge audit show FINDINGID
```

`secret reveal` and `secret export` must require an interactive confirmation or an explicit non-interactive approval flag and must always create an audit event.

## 13. Workflow Engine

Implement workflows as versioned DAGs with typed inputs and outputs.

Required baseline workflow:

```text
LoadProject
CompileScope
CheckProviders
CollectPassive
NormalizeAssets
ResolveOwnership
BuildAssetGraph
PlanSafeActive
ProbeHosts
DiscoverServices
FingerprintTechnologies
AssessDeception
PlanContentDiscovery
RunContentDiscovery
GenerateVulnerabilityCandidates
RunAllowedChecks
CollectLeakSignals
ScanApprovedRepositories
EnrichVulnerabilities
DeduplicateSignals
VerifyCandidates
ScoreConfidence
PrioritizeFindings
BuildEvidence
RenderReports
```

Every node must declare:

- Required capabilities
- Input schema
- Output schema
- Scope requirement
- Safety class
- Estimated requests
- Estimated provider credits
- Timeout
- Retry rules
- Idempotency behavior
- Cancellation behavior
- Evidence output
- Failure policy

## 14. Scheduling and Budgets

Implement hierarchical budgets:

- Global
- Project
- Provider
- Target
- Host
- Port
- Workflow
- Tool

Budget dimensions:

- Requests per second
- Requests per minute
- Concurrent connections
- Total requests
- Total bytes
- Provider credits
- Execution time
- Retry count
- Redirect count
- Evidence size

Provide dry-run planning that shows the exact tools, capabilities, targets, projected requests, credits, and policy decisions before execution.

## 15. Database and Storage

Use SQLite for standalone local mode and PostgreSQL for server mode. Keep repository interfaces database-independent.

Minimum tables or equivalent aggregates:

- projects
- authorizations
- scopes
- scopesnapshots
- assets
- assetclaims
- assetrelations
- services
- endpoints
- technologies
- observations
- exposures
- secretcandidates
- vulnerabilitycandidates
- findings
- findingrelations
- evidence
- scanruns
- jobs
- jobattempts
- providers
- providerusage
- rulesets
- auditentries
- reviewdecisions

Use migrations from the first commit. Add uniqueness, temporal, and provenance constraints. Never overwrite observations to represent a new point in time.

## 16. Reporting

Generate JSON, JSONL, Markdown, HTML, CSV, and SARIF where the target format is appropriate.

Every finding report must include:

- Stable finding ID
- Title
- Current state
- Severity
- Confidence and component breakdown
- Affected asset and endpoint
- Scope snapshot reference
- First seen and last seen
- Technical summary
- Business impact
- Evidence summary
- Reproduction steps when safe
- Verification status
- Source provenance
- CVE, CWE, CPE, GHSA, CVSS, EPSS, and KEV data when applicable
- False-positive checks performed
- Remediation guidance
- Retest status
- Redaction status

Reports must redact secrets, cookies, tokens, personal data, internal identifiers, query credentials, and unrelated response content by default.

## 17. CLI Surface

Implement a coherent command tree.

```text
reconforge init
reconforge project create
reconforge project show
reconforge scope import
reconforge scope validate
reconforge scope explain TARGET
reconforge provider list
reconforge provider configure NAME
reconforge provider health
reconforge provider usage
reconforge tool list
reconforge tool health
reconforge workflow list
reconforge workflow plan NAME
reconforge workflow run NAME
reconforge scan status RUNID
reconforge scan cancel RUNID
reconforge asset list
reconforge asset show ASSETID
reconforge asset graph ASSETID
reconforge finding list
reconforge finding show FINDINGID
reconforge finding verify FINDINGID
reconforge evidence show FINDINGID
reconforge evidence export FINDINGID
reconforge evidence timeline FINDINGID
reconforge report build RUNID
reconforge diff runs RUNIDA RUNIDB
```

Every mutating command must support machine-readable output, idempotency, explicit exit codes, and safe cancellation.

## 18. API Requirements

Expose versioned REST endpoints after the domain and workflow contracts stabilize.

Requirements:

- OpenAPI specification
- Project-scoped authorization
- Role-based access control
- Idempotency keys
- Cursor pagination
- Structured errors
- Request correlation IDs
- Server-side scope enforcement
- Redacted audit logs
- Streaming job events
- No raw secret return outside dedicated audited endpoints

Roles:

- `owner`
- `admin`
- `operator`
- `analyst`
- `reviewer`
- `viewer`

## 19. Testing Strategy

### Unit Tests

Cover parsers, normalizers, scope logic, version ranges, confidence gates, deduplication, redaction, provider pagination, rate-limit handling, and retry policy.

### Contract Tests

Create recorded sanitized fixtures for every provider and tool parser. Verify compatibility across adapter versions.

### Integration Tests

Use local containers and purpose-built mock services. Do not point automated tests at arbitrary public targets.

### False-Positive Corpus

Build a regression corpus containing:

- Soft 404 responses
- Wildcard DNS
- Catch-all virtual hosts
- CDN and WAF block pages
- Authentication redirects
- Shared hosting
- Reverse proxies
- Stale passive records
- Version backports
- Fake version banners
- Generic admin titles
- Honey services
- Example and revoked secrets
- Test credentials
- Minified source-map noise
- Duplicate provider records
- Redirected out-of-scope hosts

Every confirmed false positive must become a regression fixture with its reason code.

### Safety Tests

Prove that denied targets, out-of-scope redirects, shared infrastructure, unknown authorization, expired authorization, exhausted budgets, and disallowed template classes cannot reach active runners.

### Cross-Platform Tests

Run CI on Linux, macOS, and Windows. Test path handling, cancellation, process trees, temporary files, executable discovery, and signals or platform equivalents.

## 20. Observability

Implement structured logs, metrics, traces, and audit events with redaction at the source.

Track:

- Job latency
- Provider latency
- Provider errors
- Provider credit use
- Cache hit rate
- Tool execution failures
- Parser failures
- Findings by confidence state
- False-positive rate by detector
- Verification success rate
- Scope rejection count
- Budget rejection count
- Evidence volume
- Queue depth

Do not log target identifiers at high verbosity by default. Support keyed pseudonymous identifiers for operational telemetry.

## 21. Delivery Phases

### Phase 0: Repository Foundation

Deliver:

- Go workspace
- Monorepo directories
- Build system
- Linting
- Formatting
- Dependency policy
- License files
- Security policy
- Contributor guide
- Architecture decision record system in `docs`
- Linux, macOS, and Windows CI

Exit criteria:

- All builds pass on three operating systems.
- Package and directory naming rules are enforced.
- Production comment-line prohibition is enforced without breaking generated code or license files.
- No placeholder production package exists.

### Phase 1: Domain, Scope and Storage

Deliver:

- Domain types
- SQLite repositories
- Migrations
- Project management
- Scope parser and compiler
- Authorization snapshots
- Audit log
- Redaction primitives
- SecretVault interface

Exit criteria:

- Scope decisions are deterministic and explainable.
- Redirect and DNS pivot tests fail closed.
- Every active action requires a valid immutable scope snapshot.

### Phase 2: Provider Framework

Deliver:

- Provider registry
- Capability contracts
- Credential references
- Cache
- Rate limiter
- Credit budgets
- Pagination checkpoints
- Provider health system
- FOFA, Censys, Netlas, Shodan and LeakIX adapters

Exit criteria:

- A passive workflow can query any enabled provider through capabilities.
- Raw provider schemas never appear in domain packages.
- Provider failures do not corrupt or abort unrelated provider results.

### Phase 3: Passive Asset Graph

Deliver:

- Asset normalization
- Ownership resolver
- Relation graph
- Passive correlation
- Freshness model
- Provider deduplication
- Asset CLI

Exit criteria:

- Equivalent assets merge correctly while preserving source claims.
- Shared infrastructure and historical relations remain distinguishable.
- Every relation is traceable to evidence.

### Phase 4: Safe Active Engines

Deliver:

- DNS engine
- TCP connect engine
- HTTP probe
- TLS probe
- Fingerprint engine
- HoneySense baseline
- Budgets and cancellation

Exit criteria:

- SafeActive workflows cannot exceed compiled budgets.
- Out-of-scope pivots are blocked.
- Fingerprints expose component evidence and uncertainty.

### Phase 5: Tool Adapters

Deliver:

- Process runner
- Nmap adapter
- Nuclei adapter
- ffuf adapter
- Version checks
- Structured parsers
- Artifact manifests

Exit criteria:

- Tool crashes and malformed outputs are contained.
- Scan runs are reproducible from stored versions and plans.
- Unknown or disallowed Nuclei templates cannot run.

### Phase 6: False-Positive Engine

Deliver:

- Baselines
- Soft-404 detection
- Wildcard detection
- WAF and gateway classification
- Deduplication
- Version-range engine
- Confidence components
- Rule gates
- Review queue
- Regression corpus

Exit criteria:

- No finding is confirmed solely from a passive provider or banner version.
- Every confidence outcome is explainable.
- Regression fixtures cover all required false-positive families.

### Phase 7: Leak Intelligence

Deliver:

- LeakIntel domain model
- LeakIX normalization
- GitHub and GitLab approved repository sources
- Gitleaks and TruffleHog adapters
- Offline secret classification
- Redacted secret storage
- Optional policy-approved read-only verifiers
- HIBP verified-domain integration

Exit criteria:

- Raw secrets never appear in standard output, logs, database rows, or reports.
- Unverified ownership prevents online validation.
- Leak findings preserve minimum necessary evidence only.

### Phase 8: Vulnerability Intelligence

Deliver:

- NVD integration
- CISA KEV integration
- FIRST EPSS integration
- GHSA integration
- CPE candidate resolver
- Package and version-range matcher
- CVE prioritization

Exit criteria:

- Product and version evidence is separated from vulnerability confirmation.
- Backports and ambiguous versions cannot become confirmed findings automatically.
- CVSS, EPSS and KEV remain separate prioritization dimensions.

### Phase 9: Evidence and Reporting

Deliver:

- Encrypted evidence store
- Evidence manifests
- Timeline
- Redaction engine
- JSON, Markdown, HTML and SARIF reports
- Finding and evidence CLI

Exit criteria:

- Evidence hashes verify successfully.
- Reports are useful without exposing secrets or unrelated personal data.
- Every finding can be traced to source observations and policy decisions.

### Phase 10: API and Web Interface

Deliver:

- Versioned API
- RBAC
- Event streaming
- React interface
- Asset explorer
- Finding review
- Provider health and cost view
- Workflow planner
- Evidence timeline

Exit criteria:

- UI actions cannot bypass server-side policy.
- Every sensitive access creates an audit event.
- CLI and UI use the same domain and workflow services.

## 22. Definition of Done for Every Task

A task is complete only when:

- Implementation is production-grade.
- No production comment line was added.
- Package and directory naming rules pass.
- Public contracts are documented in `docs`.
- Unit tests pass.
- Relevant contract and integration tests pass.
- Scope and safety tests pass.
- Redaction tests pass.
- Cross-platform behavior is considered.
- Error paths are tested.
- Metrics and audit events are added where relevant.
- Migrations are included when persistence changes.
- Fixtures are sanitized.
- No secret is present in source, fixtures, logs, snapshots, or reports.
- The task has explicit acceptance evidence.

## 23. Initial Backlog

Execute in order unless a dependency requires an explicit change.

1. `T001` Create the monorepo and enforcement checks.
2. `T002` Define versioned domain contracts.
3. `T003` Implement project and authorization models.
4. `T004` Implement ScopeGuard and ScopeSnapshot.
5. `T005` Implement BudgetGuard.
6. `T006` Implement SQLite migrations and repositories.
7. `T007` Implement SecretVault and redaction primitives.
8. `T008` Implement immutable audit events.
9. `T009` Implement ProviderRegistry and capability contracts.
10. `T010` Implement provider cache, retry, pagination and credit accounting.
11. `T011` Implement FOFA adapter.
12. `T012` Implement Censys adapter.
13. `T013` Implement Netlas adapter.
14. `T014` Implement Shodan adapter.
15. `T015` Implement LeakIX adapter.
16. `T016` Implement asset normalization and stable identities.
17. `T017` Implement Ownership resolver.
18. `T018` Implement asset relation graph.
19. `T019` Implement passive correlation and freshness decay.
20. `T020` Implement workflow engine and job state machine.
21. `T021` Implement dry-run workflow planning.
22. `T022` Implement DNS engine.
23. `T023` Implement TCP connect engine.
24. `T024` Implement HTTP and TLS probe.
25. `T025` Implement Fingerprint engine.
26. `T026` Implement HoneySense.
27. `T027` Implement isolated process runner.
28. `T028` Implement Nmap adapter and XML parser.
29. `T029` Implement Nuclei adapter and JSONL parser.
30. `T030` Implement ffuf adapter and JSON parser.
31. `T031` Implement baseline and control-request engine.
32. `T032` Implement wildcard and soft-404 detection.
33. `T033` Implement WAF, CDN and authentication-gateway classification.
34. `T034` Implement observation and finding deduplication.
35. `T035` Implement version-range and prerequisite matching.
36. `T036` Implement confidence component storage and decision gates.
37. `T037` Implement review queue and decision reasons.
38. `T038` Build false-positive regression corpus.
39. `T039` Implement LeakIntel model and pipeline.
40. `T040` Implement GitHub and GitLab approved-source adapters.
41. `T041` Implement Gitleaks adapter.
42. `T042` Implement TruffleHog adapter.
43. `T043` Implement offline secret verification.
44. `T044` Implement policy-controlled online verifier framework.
45. `T045` Implement HIBP verified-domain adapter.
46. `T046` Implement GreyNoise adapter.
47. `T047` Implement urlscan adapter with safe visibility defaults.
48. `T048` Implement SecurityTrails adapter.
49. `T049` Implement NVD and CPE enrichment.
50. `T050` Implement CISA KEV enrichment.
51. `T051` Implement FIRST EPSS enrichment.
52. `T052` Implement GHSA enrichment.
53. `T053` Implement vulnerability candidate correlation.
54. `T054` Implement encrypted evidence store.
55. `T055` Implement evidence timeline and manifests.
56. `T056` Implement reporting and exports.
57. `T057` Implement run-to-run diffing.
58. `T058` Implement versioned REST API.
59. `T059` Implement RBAC and sensitive-access audit.
60. `T060` Implement web interface after CLI acceptance.

## 24. Agent Execution Rules

The implementation agent must:

1. Inspect the repository before changing it.
2. Preserve unrelated user changes.
3. Work in the listed phase order.
4. Produce a short execution plan for each phase.
5. Implement complete vertical slices instead of empty scaffolding.
6. Avoid placeholder adapters that claim support without parsing real sanitized fixtures.
7. Never invent provider fields or API behavior.
8. Use official provider documentation and record adapter assumptions in `docs`.
9. Pin dependencies and tool versions where reproducibility requires it.
10. Run relevant tests after every task.
11. Report changed files, tests, known limitations, and the next dependency.
12. Stop and request a decision when licensing, authorization, destructive behavior, credential validation, or provider terms are ambiguous.
13. Never weaken ScopeGuard, BudgetGuard, redaction, or audit controls to make a test pass.
14. Never introduce comments into production source code.
15. Never place underscores in project-controlled module, package, or directory names.

## 25. Product Success Criteria

ReconForge is successful when it can take an explicitly authorized project, compile its scope, collect passive intelligence from several providers, resolve and correlate assets, plan a bounded active workflow, run approved discovery tools, normalize results, suppress known false-positive families, correlate vulnerability intelligence, detect defensive leak signals, preserve redacted evidence, and generate a reproducible report without exposing secrets or crossing authorization boundaries.

The final product must be measurably better than a shell script that runs tools sequentially. Its value must come from decisions, evidence, safety, correlation, confidence, and repeatability.
