# First-Party Engines

nullrecon owns its discovery and detection logic. No external scanner binary is
invoked; every engine is native Go. External tools such as ffuf or nuclei are
studied only as references for detection behaviour, never wrapped or bundled.

## Content Discovery (`engines/contentdiscovery`)

Native directory and file discovery. It replaces the role a fuzzing tool would
play, but the calibration and false-positive suppression are first-party.

### Calibration

Before probing wordlist paths the engine issues a small number of requests to
random, almost-certainly-absent paths (`nr404-*`). From those responses it
derives a `Baseline`:

- `CatchAll`: the server answered success for random paths (a soft-404 or
  wildcard responder).
- `StableLength` / `Length`: random probes shared a byte length.
- `StableShape` / `Words` / `Lines`: random probes shared word and line counts,
  which survives soft-404 pages that reflect the requested path into the body.
- `BodyHashes`: distinct response body hashes observed for random paths.

### Classification

Each matched response is labelled:

- `redirect`: 3xx responses, recorded with their `Location`.
- `noise`: matches the calibration baseline by body hash, exact length, or the
  word/line shape signature; also responses that fall inside a dominant
  same-length cluster (a catch-all with varying but clustered output).
- `filtered`: length appears in the caller-supplied `FilterSizes` set.
- `candidate`: everything else. Candidates are the only responses promoted to
  stored endpoints.

A candidate is an `Endpoint`, never a finding. Discovery states that a path
exists; it does not assert a weakness.

### Safety and budgets

- Every request is re-evaluated against the compiled `ScopeSnapshot` with the
  `httpget` action before it is sent; denied paths and out-of-scope hosts are
  counted as `Blocked` and never requested.
- Every request draws from the run `BudgetGuard`; budget exhaustion blocks
  further requests rather than exceeding the limit.
- Redirects are not followed; the raw 3xx and its target are recorded so a pivot
  is never taken implicitly.

### Wordlists

`DefaultWords` is a curated common list. `WordsForTechnologies` augments it with
product-specific paths when fingerprinting has already identified a technology
on the asset (for example WordPress or Jenkins paths). Extensions come from
`DefaultExtensions`.

### Orchestration

`PlanContentDiscovery` builds targets from HTTP endpoints already confirmed and
stored by `DiscoverServices` (source `webprobe`). Each candidate base URL is
gated with the `contentdiscovery` action class, which requires `AuthorizedTest`
mode and an explicit `scanClasses` grant in scope. Without that authorization the
plan yields no targets and the run performs no requests, so the pipeline fails
closed. `RunContentDiscovery` scans each authorized target and stores only
candidate and redirect endpoints.

## Subdomain Discovery (`engines/dnsbrute`)

Native, API-free subdomain discovery. It resolves an embedded wordlist of
common subdomains against the target domain and keeps only names that
actually resolve, so it emits zero false positives by construction — unlike
passive certificate-transparency sources that also list dead or historical
names. Lookups rotate across public resolvers (`1.1.1.1`, `8.8.8.8`,
`9.9.9.9`, `8.8.4.4`) with per-lookup retry and a worker pool, so flaky
resolution does not drop live hosts. Every candidate is scope-gated with the
`dnsresolve` action and draws from the run budget. The resolver is an
interface, so tests inject a fake and never touch the network. Against a live
domain it recovered subdomains that a passive multi-source tool missed while
reporting nothing that did not resolve. `nullrecon subdomain DOMAIN --project
SLUG --label LABEL --mode safeactive`.

## Origin IP (`engines/originip`)

Discovers real IP addresses hiding behind CDN, WAF, and DDoS-protection
services. The detection logic is native; the embedded CDN/WAF range data was
adapted from the nullcloud project into a versioned ruleset
(`engines/originip/cdnranges.json`, `nr.rules/v1`) covering 21 providers and
several thousand IPv4 and IPv6 networks.

### Classification

Each resolved IP is checked against the provider network map:

- In a provider range: `protected` (the IP belongs to the fronting service).
- Public and outside every provider range: an origin `candidate`.
- Private, loopback, reserved, link-local, or multicast: excluded entirely.

Classification is passive and makes no requests.

### Verification (false-positive control)

A candidate is never reported as a confirmed origin on classification alone. The
engine fetches a reference from the protected site (`https://<domain>/`) and then
fetches each candidate `https://<ip>/` with the original `Host` header, comparing
status, page title, first-8KB body hash, and favicon mmh3 hash. Weighted scoring
yields a state:

- `confirmed`: a strong signal (body hash or favicon) matched with score ≥ 0.5.
- `likely`: exact title match with score ≥ 0.5.
- `potential`: a weaker partial signal matched.
- `needsreview`: not probed — see safety below.

Responses that answer but match nothing are dropped, not reported.

### Safety

Every candidate IP is a discovered pivot, so it is re-evaluated against the scope
snapshot before any traffic is sent. A candidate outside authorized scope is
recorded as `needsreview` with `scopeBlocked` and is never probed, so origin
verification fails closed. The reference fetch is likewise scope-gated, and every
request draws from the run budget.

### CLI

`nullrecon origin --domain DOMAIN --project SLUG --label LABEL --mode MODE
[--host SUBDOMAIN ...] [--ip IP ...]` resolves the domain and any supplied
subdomains, adds explicit candidate IPs, and runs classification and verification.

## Exposure Detection (`engines/exposure`)

Native detection of exposed sensitive files and misconfigurations (leaked
`.git` and `.env` files, backups, `wp-config` backups, Spring Boot actuators,
directory listings, `phpinfo`, and similar). Signatures are a versioned embedded
ruleset (`engines/exposure/signatures.json`, `nr.rules/v1`).

### Content-verified, not status-only

A path returning 200 is never a finding on its own. Every signature carries
content matchers — required substrings, an at-least-one set, forbidden
substrings, and an optional regex — and a finding is `confirmed` only when the
body satisfies them. Soft-404 pages and catch-all responders are filtered out by
`mustNotContain` HTML markers and by the absence of the real signature content,
so a wildcard 200 does not produce false positives.

### Secret safety

Findings in the `leak` category (exposed secrets and credentials) never carry a
raw body preview. Other categories include a preview capped at 256 bytes and run
through the redactor, so secret material never reaches output. The full body is
only ever handed to the encrypted evidence store, never printed.

### Safety and budgets

Each signature request is scope-gated with the `httpget` action and draws from
the run budget, so denied paths and exhausted budgets block requests. Redirects
are not followed.

### CLI

`nullrecon exposure --project SLUG --label LABEL --mode MODE (--url URL |
--domain DOMAIN) ...` scans each target against the signature set.

## Secret Detection (`engines/secretscan`)

Native detection of leaked secrets in any fetched content (HTTP bodies, exposed
files). Detectors are a versioned code-defined set (`DetectorsVersion`,
`nr.rules/v1`) covering AWS keys, Google API keys, GitHub and npm tokens, Slack
tokens and webhooks, Stripe keys, JWTs, and private keys, plus an entropy-gated
generic assignment detector.

### False-positive and secret safety

A regex match is not enough. Each candidate passes placeholder detection
(documented example keys such as the AWS `AKIAIOSFODNN7EXAMPLE`, `your_*`
markers, repeated runs) and, where the detector defines it, a Shannon-entropy
gate. Only survivors are reported; the rest are counted as suppressed.

The raw secret never leaves the engine. Each candidate carries an irreversible
sha256 fingerprint (for dedup) and a masked preview (`prefix***(len=N)`), never
the value. When the exposure engine runs with secret detectors, confirmed leaks
attach these fingerprint-only hits — so an exposed `.env` reports which secret
types leaked without ever emitting the secret. The orchestrator persists these
as `SecretCandidate` records keyed by fingerprint.

## Vulnerability Intelligence (`engines/vulnmatch`)

Native version-range vulnerability matching. It correlates fingerprinted
technologies against an embedded, versioned ruleset (`engines/vulnmatch/rules.json`,
`nr.rules/v1`) of well-documented CVEs with concrete affected ranges (Log4Shell,
Spring4Shell, Struts2, Heartbleed, Apache path traversal, PHP-FPM, Confluence
OGNL, nginx smuggling). Rules carry CVSS, EPSS, KEV, and prerequisite metadata.

### Version comparison

The matcher parses dotted versions natively, with two ordering rules external
data demands: an alphabetic patch suffix attached to the last numeric segment
sorts ascending (OpenSSL `1.0.1 < 1.0.1f < 1.0.1g`), while a `-`/`+` pre-release
suffix sorts before its release (`2.0.0-rc1 < 2.0.0`). Constraints are
space-separated comparators combined with AND inside one expression, and the
`affected` array combines expressions with OR.

### False-positive control

A candidate is emitted only when a concrete version was fingerprinted and it
falls inside an affected range; a missing or unparseable version yields nothing,
and a vendor mismatch skips the rule. Crucially, a version-range match is not a
confirmed vulnerability: prerequisites are unverified and no exploit was
attempted. Findings are created with `Prerequisite` and `ActiveVerification` at
zero, so the confidence model caps them at `potential`/`likely` and the
no-passive-confirm rule prevents any `confirmed` state. `nullrecon vuln list
--project SLUG` lists stored candidates and the KEV count.

## Confidence and False-Positive Control (`analysis/confidence`)

A single weighted, gated model decides a finding's confidence value and state.
Positive evidence components (parse, ownership, freshness, fingerprint, version,
prerequisite, cross-source, active-verification) are weighted and summed;
deception, shared-infrastructure, gateway, and staleness penalties are
subtracted. Rule gates then cap the result: a missing mandatory component caps
at 0.25, low ownership caps at 0.5, and a strong deception signal caps at 0.4.

The decisive false-positive rule is structural: a finding cannot reach
`confirmed` without either active verification (≥ 0.8) or independent
cross-source corroboration (≥ 0.5). The weighting alone keeps a passive-only
finding below the confirmed threshold, and a defensive gate downgrades any that
slip through. The `ScoreConfidence` workflow node recomputes every finding's
state through this model as the single source of truth.

## Reporting (`reporting/renderer`)

Renders findings into JSON, Markdown, and SARIF 2.1.0. The report model is a
versioned `nr.report/v1` document carrying findings, per-severity and
per-state counts, exposure and vulnerability/KEV counts, and a secret summary
that lists detector counts only — never a raw secret or preview value. SARIF severity maps to `error`/`warning`/`note` so
findings load into code-scanning dashboards. The `RenderReports` workflow node
stores a JSON report artifact and records counts; `nullrecon report build
--project SLUG [--format json|markdown|sarif] [--out FILE]` renders on demand.
