# ADR 0001: Monorepo layout and Go workspace

## Status

Accepted.

## Context

nullrecon coordinates many capabilities (passive intelligence, active discovery, tool
adapters, correlation, evidence, reporting) that must share one normalized data model and one
workflow engine while staying isolated behind contracts.

## Decision

Use a single monorepo with the directory layout described in the repository README. Use one
Go module at the repository root plus a `go.work` workspace. Application entry points live
under `apps`, reusable capabilities under `core`, `domain`, `engines`, `providers`, `tools`,
`analysis`, `platform`, and `reporting`, and shared versioned primitives under `contracts`.

A single root module is chosen over many nested modules because internal package boundaries
already provide isolation, cross-package refactors stay atomic, and dependency versions stay
uniform. If a concrete boundary (for example the web app toolchain or a plugin system)
requires separation, a nested module may be added with its own ADR.

## Consequences

- Import paths are stable and internal visibility is enforced by package design.
- All Go code builds and tests with a single `go build ./...` / `go test ./...`.
- The React interface under `apps/web` keeps its own toolchain and does not affect Go builds.
