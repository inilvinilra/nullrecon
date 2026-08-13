CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE authorizations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE scopes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    label TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (project_id, label)
);

CREATE TABLE scopesnapshots (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    authorization_id TEXT NOT NULL REFERENCES authorizations(id),
    mode TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    data TEXT NOT NULL,
    compiled_at TEXT NOT NULL
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    class TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (project_id, kind, value)
);
CREATE INDEX assets_project ON assets(project_id);

CREATE TABLE assetclaims (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    project_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_id TEXT,
    observed_at TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    raw_hash TEXT,
    data TEXT NOT NULL,
    UNIQUE (asset_id, source, source_id, observed_at)
);
CREATE INDEX assetclaims_project ON assetclaims(project_id);

CREATE TABLE assetrelations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    from_asset TEXT NOT NULL REFERENCES assets(id),
    to_asset TEXT NOT NULL REFERENCES assets(id),
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (from_asset, to_asset, kind)
);

CREATE TABLE services (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, protocol, port, observed_at)
);

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, url, method)
);

CREATE TABLE technologies (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    product TEXT NOT NULL,
    version TEXT,
    method TEXT NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, product, version, method)
);

CREATE TABLE observations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    raw_hash TEXT,
    data TEXT NOT NULL
);
CREATE INDEX observations_asset_time ON observations(asset_id, observed_at);

CREATE TABLE exposures (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    category TEXT NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE TABLE secretcandidates (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT,
    detector TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    preview TEXT NOT NULL,
    location TEXT NOT NULL,
    validation TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (project_id, detector, fingerprint, location)
);

CREATE TABLE vulnerabilitycandidates (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    cve TEXT,
    ghsa TEXT,
    matched_by TEXT NOT NULL,
    state TEXT NOT NULL,
    data TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, cve, matched_by)
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    severity TEXT NOT NULL,
    fingerprint_key TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE (project_id, fingerprint_key)
);
CREATE INDEX findings_project_state ON findings(project_id, state);

CREATE TABLE findingrelations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    from_id TEXT NOT NULL REFERENCES findings(id),
    to_id TEXT NOT NULL REFERENCES findings(id),
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (from_id, to_id, kind)
);

CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    finding_id TEXT,
    run_id TEXT,
    kind TEXT NOT NULL,
    storage_ref TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX evidence_finding ON evidence(finding_id);

CREATE TABLE scanruns (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    workflow TEXT NOT NULL,
    status TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES scanruns(id),
    node TEXT NOT NULL,
    status TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    checkpoint BLOB,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (run_id, node)
);

CREATE TABLE jobattempts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    number INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE (job_id, number)
);

CREATE TABLE providers (
    name TEXT PRIMARY KEY,
    adapter_version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    config TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE providerusage (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    project_id TEXT NOT NULL,
    credits INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE (provider, project_id, window_start)
);

CREATE TABLE rulesets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (name, version)
);

CREATE TABLE auditentries (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    project_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_hash TEXT,
    reason TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE reviewdecisions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    model_revision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
