# Roadmap

Delivery phases (exit criteria per phase are verified by tests and CI):

0. Repository foundation: workspace, enforcement checks, CI on Linux/macOS/Windows.
1. Domain, scope and storage: domain types, SQLite repositories, migrations, scope
   compiler, audit log, redaction, secret vault.
2. Provider framework: registry, capabilities, cache, rate limits, credits, pagination;
   FOFA, Censys, Netlas, Shodan, LeakIX adapters.
3. Passive asset graph: normalization, ownership, relations, correlation, freshness.
4. Safe active engines: DNS, TCP connect, HTTP/TLS probe, fingerprint, HoneySense.
5. Native detection engines: content discovery, native vulnerability checks, native
   secret detection. No external scanner binaries are wrapped (see ADR 0005).
6. False-positive engine: baselines, dedup, version ranges, confidence gates, review queue.
7. Leak intelligence: LeakIntel, GitHub/GitLab, Gitleaks/TruffleHog, HIBP.
8. Vulnerability intelligence: NVD, CISA KEV, EPSS, GHSA, CPE resolution.
9. Evidence and reporting: encrypted store, manifests, timeline, JSON/MD/HTML/SARIF.
10. API and web interface: versioned REST, RBAC, event streaming, React UI.
