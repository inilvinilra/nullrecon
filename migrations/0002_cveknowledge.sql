CREATE TABLE cveknowledge (
    cve TEXT PRIMARY KEY,
    cvss_score REAL,
    cvss_vector TEXT,
    severity TEXT,
    epss REAL,
    kev INTEGER NOT NULL DEFAULT 0,
    kev_due_date TEXT,
    source TEXT NOT NULL,
    published TEXT,
    last_modified TEXT,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX cveknowledge_kev ON cveknowledge(kev);
CREATE INDEX cveknowledge_severity ON cveknowledge(severity);

CREATE TABLE cveproduct (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve TEXT NOT NULL REFERENCES cveknowledge(cve) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    range_start_incl TEXT,
    range_start_excl TEXT,
    range_end_incl TEXT,
    range_end_excl TEXT,
    exact_version TEXT
);
CREATE INDEX cveproduct_product ON cveproduct(product);
CREATE INDEX cveproduct_cve ON cveproduct(cve);
