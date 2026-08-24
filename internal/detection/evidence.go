package detection

import (
	"encoding/json"
	"time"

	"sakanner/pkg/models"
)

// RequestResponseEvidence is the one, official structured shape a
// detector should populate to explain a finding backed by an HTTP
// probe -- so every detector's evidence is reliably machine-readable in
// the same shape, instead of each inventing its own ad hoc string
// format. It answers "why does this detector believe a vulnerability
// exists," never just "detector says vulnerable."
//
// It is JSON-marshaled into models.Evidence.Content (with Kind
// models.EvidenceKindRequestResponse) rather than becoming a new
// top-level, separately-persisted model: models.Evidence/Finding
// already exist, are already wired through storage end to end, and
// nothing about how they're persisted needed to change for this to be
// structured -- see docs/phase-3-1-detection-engine.md "Evidence
// model."
//
// Detectors must not populate Request/Response with credentials,
// session tokens, or other secrets observed in the exchange -- capture
// only what is needed to demonstrate the vulnerability (e.g. redact an
// Authorization header's value, keep only its presence).
type RequestResponseEvidence struct {
	Request          string            `json:"request,omitempty"`  // request line, e.g. "GET /sqli/vulnerable?id=%27+OR+%271%27%3D%271 HTTP/1.1"
	Response         string            `json:"response,omitempty"` // status line, e.g. "HTTP/1.1 200 OK"
	StatusCode       int               `json:"status_code,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	ResponseFragment string            `json:"response_fragment,omitempty"` // the specific snippet that triggered detection
	Parameter        string            `json:"parameter,omitempty"`
	Payload          string            `json:"payload,omitempty"`
	Observation      string            `json:"observation,omitempty"` // what was observed, in one sentence
	Reason           string            `json:"reason,omitempty"`      // why that observation indicates the vulnerability
}

// NewRequestResponseEvidence marshals e into a models.Evidence ready to
// append to a Finding's Evidence slice. A marshal failure is never
// expected (every field here is a plain string/int/map), but if it ever
// happened, this falls back to a plain-text Kind carrying e.Observation
// so a bug in evidence-building degrades to a readable-but-unstructured
// record rather than silently dropping the finding's evidence entirely.
func NewRequestResponseEvidence(id, findingID string, e RequestResponseEvidence) models.Evidence {
	return NewTypedRequestResponseEvidence(models.EvidenceKindRequestResponse, id, findingID, e)
}

// NewTypedRequestResponseEvidence is NewRequestResponseEvidence with an
// explicit models.EvidenceKind, for a detector that wants to record more
// than one evidence record per finding -- most commonly a
// models.EvidenceKindBaseline record alongside the existing
// models.EvidenceKindRequestResponse one. This is a purely generic,
// detector-independent serialization helper: it carries no
// vulnerability-specific logic and does not change what any detector
// decides is a finding, only what gets recorded about work the detector
// already did. See docs/phase-3-11-scan-orchestrator.md "Real evidence
// integration."
func NewTypedRequestResponseEvidence(kind models.EvidenceKind, id, findingID string, e RequestResponseEvidence) models.Evidence {
	now := time.Now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return models.Evidence{ID: id, FindingID: findingID, Kind: models.EvidenceKindText, Content: e.Observation, CreatedAt: now}
	}
	return models.Evidence{ID: id, FindingID: findingID, Kind: kind, Content: string(b), CreatedAt: now}
}
