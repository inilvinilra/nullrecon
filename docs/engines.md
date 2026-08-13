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
