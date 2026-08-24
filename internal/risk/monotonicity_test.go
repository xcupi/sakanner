package risk

import (
	"testing"

	"sakanner/pkg/models"
)

// Monotonicity (task section 24): "If any of these properties fail:
// PHASE 3.9 FAIL." These four properties hold by mathematical
// construction (Score is a product of non-negative factors from
// tables whose values are non-decreasing in "strength" order -- see
// weights.go -- and math.Round is itself a non-decreasing function),
// but are verified exhaustively here rather than trusted.

func TestMonotonicity_SeverityIncreaseNeverDecreasesScore(t *testing.T) {
	order := []models.Severity{models.SeverityLow, models.SeverityMedium, models.SeverityHigh, models.SeverityCritical}
	for _, conf := range allConfidences {
		for _, ver := range allVerifications {
			for _, exp := range allExposures {
				prev := -1
				for _, sev := range order {
					score := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
					if score < prev {
						t.Fatalf("PHASE 3.9 FAIL: severity increase decreased score (severity=%s confidence=%s verification=%s exposure=%s): %d < previous %d", sev, conf, ver, exp, score, prev)
					}
					prev = score
				}
			}
		}
	}
}

func TestMonotonicity_ConfidenceIncreaseNeverDecreasesScore(t *testing.T) {
	order := []ConfidenceTier{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
	for _, sev := range allSeverities {
		for _, ver := range allVerifications {
			for _, exp := range allExposures {
				prev := -1
				for _, conf := range order {
					score := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
					if score < prev {
						t.Fatalf("PHASE 3.9 FAIL: confidence increase decreased score (severity=%s confidence=%s verification=%s exposure=%s): %d < previous %d", sev, conf, ver, exp, score, prev)
					}
					prev = score
				}
			}
		}
	}
}

func TestMonotonicity_VerificationIncreaseNeverDecreasesScore(t *testing.T) {
	order := []VerificationTier{VerificationUnverified, VerificationSuspicious, VerificationVerified}
	for _, sev := range allSeverities {
		for _, conf := range allConfidences {
			for _, exp := range allExposures {
				prev := -1
				for _, ver := range order {
					score := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
					if score < prev {
						t.Fatalf("PHASE 3.9 FAIL: verification increase decreased score (severity=%s confidence=%s verification=%s exposure=%s): %d < previous %d", sev, conf, ver, exp, score, prev)
					}
					prev = score
				}
			}
		}
	}
}

func TestMonotonicity_ExposureIncreaseNeverDecreasesScore(t *testing.T) {
	// INTERNAL(0.60) < RESTRICTED(0.75) < INTERNET_FACING(1.00) is the
	// strength order this project's weight table defines; UNKNOWN
	// (0.70) sits between INTERNAL and RESTRICTED numerically and is
	// tested separately below rather than folded into this strictly
	// increasing chain (task section 24 tests "if exposure increases,"
	// which only has a well-defined meaning for the 3 ordered,
	// known-exposure values).
	order := []ExposureTier{ExposureInternal, ExposureRestricted, ExposureInternetFacing}
	for _, sev := range allSeverities {
		for _, conf := range allConfidences {
			for _, ver := range allVerifications {
				prev := -1
				for _, exp := range order {
					score := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
					if score < prev {
						t.Fatalf("PHASE 3.9 FAIL: exposure increase decreased score (severity=%s confidence=%s verification=%s exposure=%s): %d < previous %d", sev, conf, ver, exp, score, prev)
					}
					prev = score
				}
			}
		}
	}
}

func TestMonotonicity_UnknownExposureBetweenInternalAndRestricted(t *testing.T) {
	// UNKNOWN(0.70) is documented to sit strictly between
	// INTERNAL(0.60) and RESTRICTED(0.75) -- confirmed directly, not
	// just asserted in a comment.
	for _, sev := range allSeverities {
		for _, conf := range allConfidences {
			for _, ver := range allVerifications {
				internal := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureInternal}).RiskScore
				unknown := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureUnknown}).RiskScore
				restricted := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureRestricted}).RiskScore
				if unknown < internal || restricted < unknown {
					t.Errorf("UNKNOWN exposure not between INTERNAL and RESTRICTED for severity=%s confidence=%s verification=%s: INTERNAL=%d UNKNOWN=%d RESTRICTED=%d", sev, conf, ver, internal, unknown, restricted)
				}
			}
		}
	}
}
