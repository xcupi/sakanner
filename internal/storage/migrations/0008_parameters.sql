CREATE TABLE parameters (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    endpoint_id     TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    location        TEXT NOT NULL,
    classification  TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    value           TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',
    content_type    TEXT NOT NULL DEFAULT '',
    required        INTEGER,
    evidence_ref    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_parameters_scan_job_id ON parameters(scan_job_id);
CREATE INDEX idx_parameters_endpoint_id ON parameters(endpoint_id);
