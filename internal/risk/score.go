package risk

import "math"

// Score computes a deterministic ScoreBreakdown from factors -- task
// section 3's formula:
//
//	raw_score = severity_base × confidence_multiplier × verification_multiplier × exposure_multiplier
//
// clamped to [0, 100] and rounded to the nearest integer (round-half-
// away-from-zero, via math.Round -- deterministic, never data- or
// time-dependent). This is the ONLY function in this package that
// performs arithmetic on the weight tables in weights.go; every other
// entry point (Engine.Assess, DeriveFactors) eventually calls this one
// so there is exactly one place the formula is implemented.
//
// Score never panics and never returns a value outside [0, 100],
// regardless of what RiskFactors contains -- see clampScore and
// security_test.go's adversarial-input coverage.
func Score(factors RiskFactors) ScoreBreakdown {
	base, recognized := severityBase[factors.Severity]
	if !recognized {
		base = unknownSeverityBase
	}

	confMult, ok := confidenceMultiplier[factors.Confidence]
	if !ok {
		confMult = confidenceMultiplier[ConfidenceLow] // task section 20: unknown confidence -> LOW
	}
	verMult, ok := verificationMultiplier[factors.Verification]
	if !ok {
		verMult = verificationMultiplier[VerificationUnverified] // unknown verification -> UNVERIFIED
	}
	expMult, ok := exposureMultiplier[factors.Exposure]
	if !ok {
		expMult = exposureMultiplier[ExposureUnknown] // unknown exposure -> UNKNOWN
	}

	raw := float64(base) * confMult * verMult * expMult
	riskScore := clampScore(raw)

	return ScoreBreakdown{
		SeverityBase:           base,
		SeverityRecognized:     recognized,
		ConfidenceMultiplier:   confMult,
		VerificationMultiplier: verMult,
		ExposureMultiplier:     expMult,
		RawScore:               raw,
		RiskScore:              riskScore,
		Priority:               PriorityForScore(riskScore),
	}
}

// clampScore rounds raw deterministically and clamps it into [0, 100]
// -- task sections 3-4, 21, 25. NaN and both signs of Infinity (task
// section 25's adversarial list) are handled explicitly before
// rounding rather than left to produce an undefined int conversion:
// NaN and -Inf are treated as the floor (0), +Inf as the ceiling
// (100) -- the same "never assume the strongest value silently"
// caution as everywhere else in this package, except +Inf, which is
// unambiguously "at least as large as the maximum" and is clamped to
// the maximum rather than arbitrarily zeroed.
func clampScore(raw float64) int {
	switch {
	case math.IsNaN(raw):
		return 0
	case math.IsInf(raw, -1):
		return 0
	case math.IsInf(raw, 1):
		return 100
	}
	rounded := math.Round(raw)
	if rounded < 0 {
		return 0
	}
	if rounded > 100 {
		return 100
	}
	return int(rounded)
}

// PriorityForScore classifies a 0-100 integer score into a Priority
// band -- task section 4's exact boundaries. Pure integer comparison,
// no floating-point involved, so there is no boundary ambiguity: 49 is
// unambiguously LOW, 50 is unambiguously MEDIUM. A score outside
// [0, 100] (task section 21's 101/-5-shaped boundary tests) is
// defensively clamped first rather than trusted -- this function is
// exported and may be called directly with a value that didn't pass
// through clampScore.
func PriorityForScore(score int) Priority {
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	switch {
	case score >= priorityCriticalMin:
		return PriorityCritical
	case score >= priorityHighMin:
		return PriorityHigh
	case score >= priorityMediumMin:
		return PriorityMedium
	default:
		return PriorityLow
	}
}
