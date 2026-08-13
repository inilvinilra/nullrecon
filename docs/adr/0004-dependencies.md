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
- Detection is performed by first-party native engines, not by wrapping external scanner
  executables (see ADR 0005). External API data providers remain permitted as data sources.

## Current approved dependencies

| Dependency | Version | Justification |
| --- | --- | --- |
| modernc.org/sqlite | pinned in go.mod | Pure-Go SQLite driver; cgo-free cross-platform local storage |

## Consequences

- `go mod tidy` changes are reviewed like code changes.
- Builds work offline after the initial module download.
