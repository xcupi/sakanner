package risk

import "sakanner/internal/correlation"

// confidenceHighThreshold/confidenceMediumThreshold bucket a
// CanonicalFinding's continuous Confidence value into a ConfidenceTier
// -- matching internal/correlation's own confidenceTier bucketing
// thresholds (0.75/0.4), for consistency between how Phase 3.8 talks
// about a finding's confidence and how Phase 3.9 scores it. Comparison
// against NaN is always false in Go, so a NaN Confidence (task section
// 25's adversarial list) safely and silently falls through to
// ConfidenceLow without any special-casing -- see security_test.go.
const (
	confidenceHighThreshold   = 0.75
	confidenceMediumThreshold = 0.4
)

func confidenceTierOf(c float64) ConfidenceTier {
	switch {
	case c >= confidenceHighThreshold:
		return ConfidenceHigh
	case c >= confidenceMediumThreshold:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// verificationTierOf derives a VerificationTier from a
// CanonicalFinding's Phase 3.8 Status and Confidence -- task section
// 7's "use existing finding evidence... do not infer VERIFIED solely
// from severity" and section 19's "the risk engine must remain
// independent from detector implementation" (this reads only
// Phase 3.8's own already-computed Status/Confidence fields, never a
// detector's raw evidence content).
//
// correlation.StatusConfirmed means 2+ INDEPENDENTLY-signatured pieces
// of evidence corroborated the same identity (see
// docs/phase-3-8-finding-correlation.md "Finding status") -- the
// strongest verification signal available: multiple different
// observations agreeing, not just one detector run's own confidence
// claim. That independently-corroborated case maps to VERIFIED
// unconditionally.
//
// A finding still at correlation.StatusNew (exactly one distinct
// evidence signature so far) is treated as SUSPICIOUS when that
// single observation is itself HIGH confidence (matching every real
// detector's own "confirmed via controlled marker" tier -- see task
// section 7's per-detector examples, all of which correspond to each
// detector's ~0.9+ confidence case), and UNVERIFIED otherwise. This
// keeps Verification a genuinely independent axis from Confidence
// rather than a renamed copy of it: a HIGH-confidence single
// observation is SUSPICIOUS (strong, but not yet independently
// corroborated), while a MEDIUM-confidence finding that a SECOND,
// distinct piece of evidence also corroborates is VERIFIED (weaker
// individually, but agreed upon by more than one observation).
func verificationTierOf(cf correlation.CanonicalFinding) VerificationTier {
	if cf.Status == correlation.StatusConfirmed {
		return VerificationVerified
	}
	if confidenceTierOf(cf.Confidence) == ConfidenceHigh {
		return VerificationSuspicious
	}
	return VerificationUnverified
}

// exposureOf resolves Exposure from an optional, caller-supplied
// AssetContext -- task section 8's "derive only from existing
// scan/recon information; do not perform additional network
// discovery." This project's current CanonicalFinding model (Phase
// 3.8) carries no internet-facing/internal/restricted classification
// for any asset -- there is no recon stage yet that determines this --
// so every REAL finding defaults to ExposureUnknown unless a caller
// explicitly supplies one via AssetContext (e.g. a future phase that
// does track this, or an operator-supplied scope annotation). This is
// the conservative default task section 8 requires ("if exposure is
// unknown: UNKNOWN. Do not assume internet-facing"), not a gap papered
// over silently -- see docs/phase-3-9-risk-scoring.md "Limitations."
func exposureOf(ctx *AssetContext) ExposureTier {
	if ctx == nil || ctx.Exposure == "" {
		return ExposureUnknown
	}
	return ctx.Exposure
}

// DeriveFactors maps a real CanonicalFinding (plus optional asset
// context) to RiskFactors -- the ONLY place this package reads a
// CanonicalFinding's fields to build factors from real detector
// output. Severity is passed through completely unmodified (task
// section 1: the original severity must never be altered by risk
// scoring); Score's own severityBase lookup handles an unrecognized
// value conservatively (see weights.go), so DeriveFactors does no
// validation of its own.
func DeriveFactors(cf correlation.CanonicalFinding, ctx *AssetContext) RiskFactors {
	return RiskFactors{
		Severity:     cf.Severity,
		Confidence:   confidenceTierOf(cf.Confidence),
		Verification: verificationTierOf(cf),
		Exposure:     exposureOf(ctx),
	}
}
