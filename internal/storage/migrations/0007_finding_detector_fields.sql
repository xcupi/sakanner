-- Phase 3.1: the detection engine's normalized Finding model needs a
-- stable detector identity and dial-target fields distinct from the
-- path-only affected_endpoint/affected_parameter columns already here
-- since Phase 1. See pkg/models.Finding's doc comment.
ALTER TABLE findings ADD COLUMN detector_id TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN host        TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN port        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN url         TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN method      TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN source      TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_findings_detector_id ON findings(detector_id);
