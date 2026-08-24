CREATE TABLE chain_relations (
    id             TEXT PRIMARY KEY,
    scan_job_id    TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    relation_type  TEXT NOT NULL DEFAULT '',
    finding_a_id   TEXT NOT NULL DEFAULT '',
    finding_b_id   TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    evidence       TEXT NOT NULL DEFAULT '[]', -- JSON array of chains.ChainEvidence
    confidence     REAL NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);
CREATE INDEX idx_chain_relations_scan_job_id ON chain_relations(scan_job_id);

CREATE TABLE chain_candidates (
    id                TEXT PRIMARY KEY,
    scan_job_id       TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    identity_context  TEXT NOT NULL DEFAULT '',
    finding_ids       TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    relation_ids      TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    endpoints         TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    status            TEXT NOT NULL DEFAULT '',
    confidence        REAL NOT NULL DEFAULT 0,
    impact_estimate   TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT '',
    missing_evidence  TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    created_at        TEXT NOT NULL
);
CREATE INDEX idx_chain_candidates_scan_job_id ON chain_candidates(scan_job_id);
