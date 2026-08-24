CREATE TABLE endpoints (
    id              TEXT PRIMARY KEY,
    scan_job_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    http_service_id TEXT NOT NULL REFERENCES http_services(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    method          TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_endpoints_scan_job_id ON endpoints(scan_job_id);
