# nullrecon

nullrecon is an open-source, cross-platform, modular security reconnaissance, attack-surface
management, exposure detection, vulnerability correlation, leak intelligence, and evidence
platform.

One product, one CLI, one API, one normalized data model, one reporting system. Every
capability is isolated behind stable, versioned contracts.

## Status

Early development. See `docs/adr` for architecture decisions and `docs/roadmap.md` for the
delivery phase plan.

## Layout

| Path | Responsibility |
| --- | --- |
| `apps/cli` | `nullrecon` command line interface |
| `apps/api` | versioned REST API server |
| `apps/worker` | background job workers |
| `apps/web` | optional React/TypeScript interface |
| `core` | orchestrator, workflow, scheduler, policy, scopeguard, budgetguard, eventbus, health |
| `domain` | normalized asset, service, endpoint, technology, exposure, finding, evidence, identity, vulnerability, scanrun models |
| `engines` | first-party scan and analysis engines |
| `providers` | third-party intelligence provider adapters and registry |
| `tools` | isolated external tool runners and parsers |
| `analysis` | normalize, correlate, deduplicate, verify, confidence, prioritize, ownership, diff |
| `platform` | database, objectstore, secretvault, auditlog, telemetry, config, runtime |
| `reporting` | renderer, templates, export, redaction |
| `contracts` | versioned shared contracts |
| `migrations` | database migrations |
| `rules` | versioned rule sets |
| `testdata` | sanitized fixtures |
| `docs` | architecture, ADRs, operational guidance |
| `deploy` | CI enforcement checks and deployment assets |

## Build and test

```
make ci
```

or directly, cross-platform:

```
go run ./deploy/checks -root .
go vet ./...
go test ./...
go build ./...
```

## Safety baseline

nullrecon never expands a target beyond its compiled authorization scope, fails closed when
authorization is ambiguous, and never logs secrets. See `SECURITY.md` and `docs/policy.md`.

## License

AGPL-3.0-or-later. See `LICENSE`.
