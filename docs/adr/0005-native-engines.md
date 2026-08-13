# ADR 0005: Native engines over external tool wrappers

## Status

Accepted. Supersedes the external-tool-integration direction for detection engines.

## Context

The master specification described integrating external scanners (Nmap, Nuclei, ffuf,
Gitleaks, TruffleHog) through isolated runners and parsers. The project owner decided that
nullrecon must own its detection logic end to end: every scanning and detection capability is
implemented natively in Go rather than shelling out to a third-party binary.

External API data providers (FOFA, Censys, Netlas, Shodan, LeakIX, NVD, and similar) are
retained. They are queried data sources, not executed tools, and they supply passive
intelligence that cannot be reproduced locally.

## Decision

- Detection and discovery capabilities are first-party engines under `engines/`. They do not
  execute or depend on external scanner binaries.
- External scanner projects may be studied as behavioural references (for example ffuf's
  calibration approach), but their code, formats, and processes are not wrapped or bundled.
- The `tools/` runner-and-parser layer for external scanners is not part of the baseline.
- API providers remain under `providers/` as data sources with capability contracts.

## Consequences

- No runtime dependency on installed scanner binaries; behaviour is deterministic and
  reproducible from nullrecon's own code and pinned dependencies.
- Detection breadth grows through native engines (`contentdiscovery`, and later native
  vulnerability checks and secret detection) rather than template ecosystems.
- Roadmap phase 5 is reframed from tool adapters to native detection engines.
