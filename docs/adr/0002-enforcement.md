# ADR 0002: Naming, comment prohibition, and enforcement

## Status

Accepted.

## Context

The project requires production source code without comments, lower-case package and
directory names without underscores, and no generic dumping-ground packages. These rules must
be objective and machine-enforced, not review preferences.

## Decision

- `deploy/checks` is a Go program that fails CI when:
  - any production (non-`_test.go`) Go file contains a comment other than a compiler
    directive (`//go:build`, `//go:embed`, and future `//go:` directives),
  - any directory or Go file name contains an underscore or uppercase characters
    (the `_test.go` suffix is exempt as required by the toolchain),
  - any directory uses a forbidden generic name: `utils`, `helpers`, `common`, `misc`,
    `manager`,
  - any Go file is not gofmt-formatted (checked with `go/format`, so the check is
    cross-platform and needs no external binary).
- `testdata` fixture contents are exempt from naming and comment checks because fixtures must
  mirror real third-party output.
- License headers are deliberately omitted from source files; `LICENSE` at the repository
  root governs. This keeps the comment prohibition absolute and easy to enforce.

## Consequences

- All design rationale lives in `docs`, which keeps code dense and forces durable
  documentation.
- The checker is part of `make ci` and the GitHub Actions matrix on Linux, macOS, and
  Windows.
