package risk

import "sakanner/pkg/models"

// This file is the SINGLE, CENTRALIZED source of every weight,
// multiplier, and threshold the scoring formula (score.go) uses --
// task section 3's "the exact weights must be documented and
// centralized." Changing a number here changes every score this
// package ever produces; nothing else in this package (or any other
// package) defines a competing weight table.

// severityBase is task section 3's suggested base model, taken as-is.
// SeverityInfo (a real, recognized value in pkg/models.Severity that
// task section 1's LOW/MEDIUM/HIGH/CRITICAL scale doesn't mention) is
// scored conservatively low -- BELOW SeverityLow -- since an
// informational finding is, by definition, less severe than "low."
// This is a distinct case from an UNRECOGNIZED severity string (see
// unknownSeverityBase below): "info" is valid input this project's own
// model already defines, not malformed input.
var severityBase = map[models.Severity]int{
	models.SeverityInfo:     10,
	models.SeverityLow:      20,
	models.SeverityMedium:   40,
	models.SeverityHigh:     70,
	models.SeverityCritical: 90,
}

// unknownSeverityBase is the conservative fallback for a severity
// value NOT in severityBase at all (empty string, garbage, a future
// value this table hasn't been updated for) -- task section 20:
// "never silently assume the strongest value." It intentionally
// matches SeverityInfo's base (the lowest recognized value) rather
// than being scored as 0 or as CRITICAL: unknown input is treated as
// no more alarming than the lowest real severity this project defines,
// never as more, and never silently ignored (a missing/garbage
// severity still produces a real, non-zero, auditable score).
const unknownSeverityBase = 10

// confidenceMultiplier is task section 3's suggested confidence
// weights, taken as-is.
var confidenceMultiplier = map[ConfidenceTier]float64{
	ConfidenceLow:    0.50,
	ConfidenceMedium: 0.75,
	ConfidenceHigh:   1.00,
}

// verificationMultiplier is task section 3's suggested verification
// weights, taken as-is.
var verificationMultiplier = map[VerificationTier]float64{
	VerificationUnverified: 0.70,
	VerificationSuspicious: 0.85,
	VerificationVerified:   1.00,
}

// exposureMultiplier is task section 3's suggested exposure weights,
// taken as-is. Note UNKNOWN (0.70) deliberately sits BELOW RESTRICTED
// (0.75) -- an asset of undetermined exposure is treated more
// cautiously than a KNOWN-restricted one but is never assumed to be
// internet-facing (task section 8's explicit instruction), which is
// why it isn't 1.00 and isn't even the highest non-internet-facing
// value.
var exposureMultiplier = map[ExposureTier]float64{
	ExposureInternal:       0.60,
	ExposureRestricted:     0.75,
	ExposureInternetFacing: 1.00,
	ExposureUnknown:        0.70,
}

// Priority band thresholds -- task section 4. Boundaries are inclusive
// integer ranges (never floating-point comparisons -- see score.go's
// clampScore, which rounds to an int BEFORE any band comparison ever
// runs, eliminating the floating-point-boundary-ambiguity task section
// 4 explicitly warns against).
const (
	priorityCriticalMin = 90 // 90-100
	priorityHighMin     = 75 // 75-89
	priorityMediumMin   = 50 // 50-74
	// below priorityMediumMin (0-49) is PriorityLow.
)
