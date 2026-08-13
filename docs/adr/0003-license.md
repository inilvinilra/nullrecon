# ADR 0003: License: AGPL-3.0-or-later

## Status

Accepted.

## Context

nullrecon is an open-source security platform. The maintainers want improvements, including
those offered as a network service, to remain available to the community.

## Decision

The project is licensed under AGPL-3.0-or-later. The full text is in `LICENSE`.

## Consequences

- Network use of modified versions triggers source disclosure obligations, which protects
  the project from closed SaaS forks.
- Contributions are accepted under the same license; see `CONTRIBUTING.md`.
- External tools integrated through adapters (Nmap, Nuclei, ffuf, Gitleaks, TruffleHog)
  remain separate works under their own licenses; nullrecon does not bundle them until a
  licensing review approves bundling.
