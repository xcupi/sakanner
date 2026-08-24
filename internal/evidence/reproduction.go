package evidence

import (
	"sakanner/internal/correlation"
	"sakanner/internal/risk"
)

// DifferentialEvidence represents baseline vs. observed behavior --
// task section 27. Never a claim of vulnerability from length alone:
// RelevantDifference is always a short, deterministic, human-readable
// description (e.g. "status code differs" or "protected marker
// present"), never just a raw byte-count delta.
type DifferentialEvidence struct {
	BaselineStatus     int    `json:"baseline_status,omitempty"`
	ObservedStatus     int    `json:"observed_status,omitempty"`
	BaselineLength     int    `json:"baseline_length,omitempty"`
	ObservedLength     int    `json:"observed_length,omitempty"`
	RelevantDifference string `json:"relevant_difference,omitempty"`
}

// Diff computes a DifferentialEvidence from two response bodies/status
// codes -- a pure, generic function usable regardless of which
// detector (or future detector) supplies baseline/observed pairs. Not
// currently invoked by BuildEvidence for real detector output (no
// current detector persists a separate baseline evidence item -- see
// model.go's CanonicalEvidence.Baseline doc comment), but fully
// implemented and independently tested (evidence_test.go) so a future
// detector generation can use it directly.
func Diff(baselineStatus, observedStatus int, baselineBody, observedBody []byte) DifferentialEvidence {
	d := DifferentialEvidence{
		BaselineStatus: baselineStatus,
		ObservedStatus: observedStatus,
		BaselineLength: len(baselineBody),
		ObservedLength: len(observedBody),
	}
	switch {
	case baselineStatus != observedStatus:
		d.RelevantDifference = "status code differs"
	case len(baselineBody) != len(observedBody):
		d.RelevantDifference = "response length differs"
	default:
		d.RelevantDifference = "no significant difference observed"
	}
	return d
}

// ReproducibilityLevel is task section 34's classification.
type ReproducibilityLevel string

const (
	// ReproducibilityFull: all required non-secret request information
	// exists, and none of it was redacted.
	ReproducibilityFull ReproducibilityLevel = "FULL"
	// ReproducibilityPartial: some context is missing or was redacted.
	ReproducibilityPartial ReproducibilityLevel = "PARTIAL"
	// ReproducibilityLimited: the finding can be understood but cannot
	// be reproduced exactly from stored evidence.
	ReproducibilityLimited ReproducibilityLevel = "LIMITED"
)

// ReproductionInfo is task section 12's structured reproduction
// package -- built ENTIRELY from fields already present in the
// finding's own evidence (Method, URL, Parameter, Payload), never new
// detection logic, and never anything beyond what task section 13
// permits (a single, safe, already-used test value -- never a
// generated exploit, reverse shell, or destructive payload).
type ReproductionInfo struct {
	Method           string               `json:"method,omitempty"`
	URL              string               `json:"url,omitempty"` // sanitized
	Parameter        string               `json:"parameter,omitempty"`
	SafeTestValue    string               `json:"safe_test_value,omitempty"` // sanitized
	ExpectedBehavior string               `json:"expected_behavior,omitempty"`
	ObservedBehavior string               `json:"observed_behavior,omitempty"`
	Level            ReproducibilityLevel `json:"level"`
	Notes            []string             `json:"notes,omitempty"`
}

// FindingPackage is task section 29's structured output: Finding +
// Risk + Evidence + Reproduction, assembled without requiring JSON as
// the only storage format (every field here is a plain Go value,
// already using this project's existing json struct-tag convention
// for when a caller DOES want JSON -- see
// docs/phase-3-10-evidence-reproducibility.md "Canonical
// serialization").
type FindingPackage struct {
	Finding       correlation.CanonicalFinding `json:"finding"`
	Risk          risk.Assessment              `json:"risk"`
	Evidence      []CanonicalEvidence          `json:"evidence"`
	Reproduction  ReproductionInfo             `json:"reproduction"`
	Summary       string                       `json:"summary"`
	WhyVulnerable string                       `json:"why_vulnerable"`
	Limitations   []string                     `json:"limitations,omitempty"`
}
