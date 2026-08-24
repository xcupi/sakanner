CREATE TABLE targets (
    id         TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    type       TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE scope_rules (
    id         TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    type       TEXT NOT NULL,
    action     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE scan_jobs (
    id             TEXT PRIMARY KEY,
    target_ids     TEXT NOT NULL, -- JSON array
    status         TEXT NOT NULL,
    error          TEXT NOT NULL DEFAULT '',
    scope_snapshot TEXT NOT NULL, -- JSON array of ScopeRule
    config         TEXT NOT NULL DEFAULT '',
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE assets (
    id          TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_assets_scan_job_id ON assets(scan_job_id);

CREATE TABLE hosts (
    id          TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip_address  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_hosts_scan_job_id ON hosts(scan_job_id);

CREATE TABLE services (
    id          TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    banner      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_services_scan_job_id ON services(scan_job_id);

CREATE TABLE http_services (
    id            TEXT PRIMARY KEY,
    scan_job_id   TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    service_id    TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    scheme        TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    headers       TEXT NOT NULL DEFAULT '{}', -- JSON object
    tls_subject   TEXT NOT NULL DEFAULT '',
    tls_issuer    TEXT NOT NULL DEFAULT '',
    tls_not_after TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_http_services_scan_job_id ON http_services(scan_job_id);

CREATE TABLE technologies (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    http_service_id TEXT NOT NULL REFERENCES http_services(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_technologies_scan_job_id ON technologies(scan_job_id);

CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target              TEXT NOT NULL DEFAULT '',
    asset               TEXT NOT NULL DEFAULT '',
    vulnerability_type  TEXT NOT NULL DEFAULT '',
    title               TEXT NOT NULL DEFAULT '',
    description         TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT '',
    confidence          REAL NOT NULL DEFAULT 0,
    affected_endpoint   TEXT NOT NULL DEFAULT '',
    affected_parameter  TEXT NOT NULL DEFAULT '',
    detection_method    TEXT NOT NULL DEFAULT '',
    validation_status   TEXT NOT NULL DEFAULT '',
    evidence            TEXT NOT NULL DEFAULT '[]', -- JSON array of Evidence
    remediation         TEXT NOT NULL DEFAULT '',
    "references"        TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL
);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
