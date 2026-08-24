package risk

import (
	"testing"

	"sakanner/pkg/models"
)

// Matrix testing (task section 23): every combination of the
// 4×3×3×4 factor space.

var allSeverities = []models.Severity{models.SeverityLow, models.SeverityMedium, models.SeverityHigh, models.SeverityCritical}
var allConfidences = []ConfidenceTier{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
var allVerifications = []VerificationTier{VerificationUnverified, VerificationSuspicious, VerificationVerified}
var allExposures = []ExposureTier{ExposureInternal, ExposureRestricted, ExposureInternetFacing, ExposureUnknown}

func TestMatrix_ScoreAlwaysDeterministicAndBounded(t *testing.T) {
	for _, sev := range allSeverities {
		for _, conf := range allConfidences {
			for _, ver := range allVerifications {
				for _, exp := range allExposures {
					f := RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: exp}
					b1 := Score(f)
					b2 := Score(f)
					if b1 != b2 {
						t.Fatalf("Score(%+v) not deterministic: %+v vs %+v", f, b1, b2)
					}
					if b1.RiskScore < 0 || b1.RiskScore > 100 {
						t.Errorf("Score(%+v).RiskScore = %d, want in [0, 100]", f, b1.RiskScore)
					}
				}
			}
		}
	}
}

func TestMatrix_StrongerConfidenceNeverLowersScore(t *testing.T) {
	for _, sev := range allSeverities {
		for _, ver := range allVerifications {
			for _, exp := range allExposures {
				low := Score(RiskFactors{Severity: sev, Confidence: ConfidenceLow, Verification: ver, Exposure: exp}).RiskScore
				med := Score(RiskFactors{Severity: sev, Confidence: ConfidenceMedium, Verification: ver, Exposure: exp}).RiskScore
				high := Score(RiskFactors{Severity: sev, Confidence: ConfidenceHigh, Verification: ver, Exposure: exp}).RiskScore
				if med < low || high < med {
					t.Errorf("confidence not monotonic for severity=%s verification=%s exposure=%s: LOW=%d MEDIUM=%d HIGH=%d", sev, ver, exp, low, med, high)
				}
			}
		}
	}
}

func TestMatrix_StrongerExposureNeverLowersScore(t *testing.T) {
	for _, sev := range allSeverities {
		for _, conf := range allConfidences {
			for _, ver := range allVerifications {
				internal := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureInternal}).RiskScore
				restricted := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureRestricted}).RiskScore
				internetFacing := Score(RiskFactors{Severity: sev, Confidence: conf, Verification: ver, Exposure: ExposureInternetFacing}).RiskScore
				if restricted < internal || internetFacing < restricted {
					t.Errorf("exposure not monotonic for severity=%s confidence=%s verification=%s: INTERNAL=%d RESTRICTED=%d INTERNET_FACING=%d", sev, conf, ver, internal, restricted, internetFacing)
				}
			}
		}
	}
}

func TestMatrix_HigherSeverityNeverLowersScore(t *testing.T) {
	for _, conf := range allConfidences {
		for _, ver := range allVerifications {
			for _, exp := range allExposures {
				low := Score(RiskFactors{Severity: models.SeverityLow, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
				medium := Score(RiskFactors{Severity: models.SeverityMedium, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
				high := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
				critical := Score(RiskFactors{Severity: models.SeverityCritical, Confidence: conf, Verification: ver, Exposure: exp}).RiskScore
				if medium < low || high < medium || critical < high {
					t.Errorf("severity not monotonic for confidence=%s verification=%s exposure=%s: LOW=%d MEDIUM=%d HIGH=%d CRITICAL=%d", conf, ver, exp, low, medium, high, critical)
				}
			}
		}
	}
}
