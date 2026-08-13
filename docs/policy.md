# Policy and safety model

## Operating modes

| Mode | Sends traffic to target | Credential validation | Purpose |
| --- | --- | --- | --- |
| passive | no | no | cached and third-party public datasets only |
| safeactive | low-impact, authorized | no | DNS, TCP connect, bounded HTTP, TLS inspection, fingerprinting |
| authorizedtest | scope-approved checks | only with explicit grants | approved templates, discovery, non-destructive verification |
| watchonly | no | no | watchlists, report-only, unclear authorization, high-risk assets |

Enforcement lives in `core/policy` (`Decide`) and is composed with scope evaluation in
`core/scopeguard` (`Snapshot.EvaluateAction`).

## Fail-closed rules

- Unknown or expired authorization: no snapshot compiles, no active action runs.
- Unknown asset class: treated as not active.
- Redirects, CNAMEs, resolved IPs, alternate hostnames, and provider pivots are
  re-evaluated against the snapshot before use (`EvaluatePivot`).
- Denied assets, paths, and actions always win over allowed rules.
- Ports and protocols are fail-closed: an empty port list means no active port access.

## Prohibited baseline behaviors

Destructive testing, denial of service, persistence, credential abuse, data modification,
and uncontrolled exploitation are outside the product baseline. Proof-of-concept
verification is non-destructive, minimal, reproducible, and requires explicit policy
authorization.

## Secrets

- The database stores only keyed fingerprints and redacted previews of secret candidates.
- Raw secrets exist only inside `platform/secretvault` (envelope encryption, per-project
  keys) and isolated verifier processes.
- `secret reveal` / `secret export` require interactive confirmation or an explicit
  non-interactive approval flag and always write an audit event.
