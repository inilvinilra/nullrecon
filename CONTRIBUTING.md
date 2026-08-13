# Contributing

## Ground rules

1. Production Go source must not contain comments. Rationale and operational notes belong in
   `docs`. Compiler directives (`//go:build`, `//go:embed`) are exempt. The enforcement
   checker runs in CI: `go run ./deploy/checks -root .`.
2. Project-controlled module, package, and directory names are lower case and contain no
   underscores. Go test files keep the required `_test.go` suffix.
3. No generic `utils`, `helpers`, `common`, `misc`, or `manager` packages. Every package has
   one explicit responsibility and a narrow public API.
4. Provider-specific response structures never escape provider adapters. External tool
   output never escapes tool parsers.
5. Raw source artifacts and normalized records are stored separately.
6. All persisted schemas, events, provider contracts, and rule formats are versioned.
7. Every mutation is idempotent or protected by an idempotency key.
8. No secret, token, cookie, credential, or sensitive response body may appear in logs,
   tests, fixtures, or snapshots.

## Workflow

1. Open an issue describing the change and the phase it belongs to.
2. Keep changes minimal and vertical: no empty scaffolding.
3. Add or update tests: unit, contract, integration, safety as applicable.
4. Run `make ci` locally before pushing.
5. Update `docs` and the relevant ADR when contracts, storage, or safety behavior change.

## Adding a provider

See `docs/providers.md`. Record every adapter assumption in docs, use only official provider
documentation, and add sanitized recorded fixtures under `testdata`.
