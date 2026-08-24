// Package evidence implements sakanner's Phase 3.10 evidence and
// reproducibility engine: a centralized layer that consumes
// internal/correlation.CanonicalFinding values (Phase 3.8) and
// internal/risk.Assessment values (Phase 3.9) and produces a
// normalized, deterministic, bounded, secret-redacted evidence set
// plus safe reproduction instructions for each finding -- never
// vulnerability detection logic of its own.
//
// This package is entirely additive and detector-independent: it
// reads only the generic detection.RequestResponseEvidence JSON shape
// every detector already produces through the SAME shared Phase 3.1
// helper (internal/detection.NewRequestResponseEvidence) -- never a
// detector-specific field name or format. See "Detector independence"
// in docs/phase-3-10-evidence-reproducibility.md.
package evidence

import "time"

// EvidenceType is one of the 5 evidence kinds task section 3 defines.
type EvidenceType string

const (
	EvidenceTypeBaseline     EvidenceType = "BASELINE"
	EvidenceTypeProbe        EvidenceType = "PROBE"
	EvidenceTypeObservation  EvidenceType = "OBSERVATION"
	EvidenceTypeVerification EvidenceType = "VERIFICATION"
	EvidenceTypeReproduction EvidenceType = "REPRODUCTION"
)

// typeRank orders EvidenceType for deterministic sorting -- task
// section 19's recommended order.
var typeRank = map[EvidenceType]int{
	EvidenceTypeBaseline:     0,
	EvidenceTypeProbe:        1,
	EvidenceTypeObservation:  2,
	EvidenceTypeVerification: 3,
	EvidenceTypeReproduction: 4,
}

// RequestEvidence is the sanitized, bounded request side of one
// evidence item -- task section 5.
type RequestEvidence struct {
	Method    string            `json:"method,omitempty"`
	URL       string            `json:"url,omitempty"` // sanitized -- see redact.go
	Parameter string            `json:"parameter,omitempty"`
	Location  string            `json:"location,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"` // sanitized
	Body      string            `json:"body,omitempty"`    // sanitized, bounded
	Truncated bool              `json:"truncated,omitempty"`
}

// ResponseEvidence is the sanitized, bounded response side of one
// evidence item -- task section 6.
type ResponseEvidence struct {
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"` // sanitized
	Excerpt     string            `json:"excerpt,omitempty"` // sanitized, bounded
	Truncated   bool              `json:"truncated,omitempty"`
	Binary      *BinarySummary    `json:"binary,omitempty"` // set instead of Excerpt for binary content -- section 22
}

// BinarySummary describes a binary response without ever converting
// its bytes to text -- task section 22.
type BinarySummary struct {
	ContentType     string `json:"content_type"`
	SizeBytes       int    `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	SamplePrefixHex string `json:"sample_prefix_hex,omitempty"` // first few bytes only, hex-encoded
}

// RedirectEvidence captures a redirect hop, when the detector's own
// evidence recorded one -- task section 24. This package never follows
// a redirect itself; it only ever reports one the scanner's own
// scope-enforced Executor already followed and recorded.
type RedirectEvidence struct {
	InitialURL string `json:"initial_url,omitempty"`
	Status     int    `json:"status,omitempty"`
	Location   string `json:"location,omitempty"`
	FinalURL   string `json:"final_url,omitempty"`
}

// CanonicalEvidence is this package's normalized evidence model --
// task section 2's minimum field list.
type CanonicalEvidence struct {
	EvidenceID string       `json:"evidence_id"`
	FindingID  string       `json:"finding_id"`
	Type       EvidenceType `json:"type"`

	Request  RequestEvidence  `json:"request"`
	Response ResponseEvidence `json:"response"`

	// Baseline holds a SEPARATE request/response pair for differential
	// comparison, when one is available (task section 4/27) -- nil for
	// every real finding today, since no current detector persists a
	// separate baseline evidence item; see "Limitations" in
	// docs/phase-3-10-evidence-reproducibility.md.
	Baseline *DifferentialEvidence `json:"baseline,omitempty"`

	// Redirect is set only when the underlying evidence recorded one --
	// see RedirectEvidence's doc comment.
	Redirect *RedirectEvidence `json:"redirect,omitempty"`

	Observation  string `json:"observation,omitempty"`  // sanitized
	Verification string `json:"verification,omitempty"` // sanitized -- the detector's own Reason text

	Confidence float64 `json:"confidence"`

	// DetectorFields holds whatever generic key=value pairs the
	// detector's own Observation string carried -- extracted by a
	// single, detector-agnostic parser (parse.go), never by
	// detector-specific field-name knowledge. See task section 28.
	DetectorFields map[string]string `json:"detector_fields,omitempty"`

	// AuthenticationContext is safe, non-secret metadata only -- task
	// section 33. Never a credential, cookie, or token value.
	AuthenticationContext string `json:"authentication_context,omitempty"`

	// Duration is request timing, WHERE ALREADY AVAILABLE (task section
	// 26) -- zero for every real finding today, since no current
	// detector's evidence carries per-request timing; see
	// "Limitations." Excluded from the canonical hash input regardless
	// (see hash.go): timing must never affect evidence identity.
	Duration time.Duration `json:"duration,omitempty"`

	// IntegrityHash is SHA-256 (hex) over this item's canonical,
	// REDACTED content -- task sections 15-16. Deterministic: identical
	// canonical content always produces the identical hash, computed
	// over content that has ALREADY been sanitized, so the hash itself
	// can never encode a secret value either.
	IntegrityHash string `json:"integrity_hash"`

	// CollectedAt is metadata only -- task section 26/39 explicitly
	// excludes timestamps from evidence identity/hashing/ordering, so
	// this field is never read by EvidenceID, IntegrityHash, or Sort.
	CollectedAt time.Time `json:"collected_at"`
}
