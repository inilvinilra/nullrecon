# Architecture

## One product, stable contracts

nullrecon presents one CLI (`apps/cli`), one API (`apps/api`), one normalized data model
(`domain`, `contracts`), and one reporting system (`reporting`). Capabilities are isolated
behind versioned contracts so providers, tools, and engines can evolve independently.

## Data flow

1. A project defines authorization and scope (`domain/identity`, `core/scopeguard`).
2. Every run compiles an immutable `ScopeSnapshot`; its hash is stored with every job and
   finding. Active work is impossible without one.
3. `core/policy` enforces the four operating modes: `passive`, `safeactive`,
   `authorizedtest`, `watchonly`.
4. `core/budgetguard` enforces hierarchical budgets (global, project, provider, target,
   host, port, workflow, tool) across requests, bytes, credits, concurrency, time, retries,
   redirects, and evidence size.
5. Providers (`providers/*`) return normalized observations; raw responses are stored
   separately and hash-referenced.
6. Analysis (`analysis/*`) normalizes, correlates, deduplicates, verifies, and scores
   confidence; findings are only created from observations, never raw provider records.
7. Evidence (`domain/evidence`, `platform/objectstore`, `platform/secretvault`) is hashed,
   encrypted, redacted, and auditable.
8. Reports (`reporting/*`) render from findings and evidence with redaction by default.

## Failure philosophy

- Fail closed: ambiguous authorization, ownership, provider capability, or action safety
  means deny.
- Observations are immutable; new points in time are new rows.
- Every mutation is idempotent or carries an idempotency key.
- Provider data is an observation, never automatic truth.

## Layers and dependencies

Dependencies point inward only: `apps` -> `core`/`engines`/`analysis` -> `domain` ->
`contracts`. `platform` provides storage and runtime services and may be imported by any
layer above it. Provider adapters depend on `providers/registry` contracts and never expose
provider-specific response structs.
