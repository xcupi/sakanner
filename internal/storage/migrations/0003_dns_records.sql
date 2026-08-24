CREATE TABLE dns_records (
    id          TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_dns_records_scan_job_id ON dns_records(scan_job_id);
