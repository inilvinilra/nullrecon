# Security Policy

## Reporting

Report vulnerabilities privately to the maintainers listed in the repository metadata.
Do not open public issues for unpatched vulnerabilities.

## Scope

The following are in scope for reports:

- Bypass of ScopeGuard, BudgetGuard, policy mode enforcement, or redaction controls.
- Secret material appearing in logs, reports, database rows, or standard output.
- Authorization decisions that fail open instead of closed.
- Remote code execution through tool adapters, parsers, or provider responses.

## Product safety baseline

- Destructive testing, denial of service, persistence, credential abuse, data modification,
  and uncontrolled exploitation are outside the product baseline.
- Passive discovery is never treated as permission for active testing.
- Online credential validation requires explicit, policy-approved, read-only verifiers.

## Supported versions

Only the latest main branch receives security fixes until a stable release is tagged.
