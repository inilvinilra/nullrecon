# Providers

All adapters implement the capability contracts in `providers/registry`. Provider-specific
response structs never leave the adapter packages; workflows consume normalized
`registry.Record` values plus hash-referenced raw artifacts.

Credentials are resolved server-side from SecretVault via the provider's `secretRef` and are
never logged, put in process arguments, or stored in the database.

## Adapter assumptions

Assumptions are recorded from official documentation at the time of writing. When a provider
changes its API, the adapter version is bumped and fixtures are re-recorded.

### FOFA (v1.0.0)

- Endpoint `GET /api/v1/search/all` with `email`, `key`, `qbase64`, `size`, `fields`.
- Results are rows ordered by the requested `fields` list; the adapter requests
  `ip,port,protocol,host,title,server,cert,lastupdatetime` and rejects rows with unexpected
  column counts.
- Credential is stored as `email:key` in one vault blob.
- Pagination is treated as single-page within the size budget.
- Certificate values longer than 128 characters are stored hashed, never inline.

### Censys (v1.0.0)

- Endpoint `GET /api/v2/hosts/search` with `q`, `per_page`, `cursor`; bearer token auth.
- Pagination uses `result.links.next` as an opaque cursor.
- Only host fields `ip`, `name`, `services[].port`, `services[].service_name`,
  `autonomous_system` are normalized.

### Netlas (v1.0.0)

- Endpoints `/api/responses/`, `/api/domains/`, `/api/certs/` with `q` and `start` offset;
  `X-API-Key` header auth.
- Item payloads under `items[].data` are heterogeneous; the adapter extracts only the known
  keys `ip`, `port`, `uri`, `host`, `protocol`.
- Pagination advances by consumed item count against the reported `total`.

### Shodan (v1.0.0)

- Endpoints `GET /shodan/host/{ip}` and `GET /shodan/host/search`; `key` query auth.
- `vulns` is accepted in both list and object form because the API has returned both.
- Service timestamps use the documented `2006-01-02T15:04:05.999999` layout.
- Vulnerability hints are observations (`vulnhint` kind), never findings.

### LeakIX (v1.0.0)

- Endpoints `GET /search` (scopes `leak` and `service`), `GET /host/{ip}`,
  `GET /subdomains/{domain}`; `api-key` header auth.
- Leak contents are never stored; only metadata fields (type, plugin, dataset counters,
  network attribution, timestamps) are normalized.
- Dataset contents, breached records, and raw `data` payloads are dropped at the adapter
  boundary by design.
