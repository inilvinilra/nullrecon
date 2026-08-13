# ADR 0004: Dependency policy

## Status

Accepted.

## Context

Reproducibility, supply-chain hygiene, and cross-platform builds (Linux, macOS, Windows)
constrain dependency choices.

## Decision

- The Go standard library is always preferred.
- Third-party Go dependencies require a concrete justification recorded in this ADR or a new
  one, must support all three target operating systems without cgo, and are pinned by
  version in `go.mod` and verified by `go.sum`.
- External executables (Nmap, Nuclei, ffuf, Gitleaks, TruffleHog) are discovered at runtime,
  never vendored, and their versions are recorded in scan run metadata.

## Current approved dependencies

| Dependency | Version | Justification |
| --- | --- | --- |
| modernc.org/sqlite | pinned in go.mod | Pure-Go SQLite driver; cgo-free cross-platform local storage |

## Consequences

- `go mod tidy` changes are reviewed like code changes.
- Builds work offline after the initial module download.
