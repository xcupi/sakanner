package risk

import (
	"math"
	"testing"

	"sakanner/pkg/models"
)

// --- Severity/confidence/verification/exposure mapping ---------------------

func TestSeverityBase_MatchesDocumentedTable(t *testing.T) {
	cases := map[models.Severity]int{
		models.SeverityLow: 20, models.SeverityMedium: 40,
		models.SeverityHigh: 70, models.SeverityCritical: 90,
	}
	for sev, want := range cases {
		got := Score(RiskFactors{Severity: sev, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing}).SeverityBase
		if got != want {
			t.Errorf("severity base for %s = %d, want %d", sev, got, want)
		}
	}
}

func TestConfidenceMultiplier_MatchesDocumentedTable(t *testing.T) {
	cases := map[ConfidenceTier]float64{ConfidenceLow: 0.50, ConfidenceMedium: 0.75, ConfidenceHigh: 1.00}
	for tier, want := range cases {
		got := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: tier, Verification: VerificationVerified, Exposure: ExposureInternetFacing}).ConfidenceMultiplier
		if got != want {
			t.Errorf("confidence multiplier for %s = %v, want %v", tier, got, want)
		}
	}
}

func TestVerificationMultiplier_MatchesDocumentedTable(t *testing.T) {
	cases := map[VerificationTier]float64{VerificationUnverified: 0.70, VerificationSuspicious: 0.85, VerificationVerified: 1.00}
	for tier, want := range cases {
		got := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: tier, Exposure: ExposureInternetFacing}).VerificationMultiplier
		if got != want {
			t.Errorf("verification multiplier for %s = %v, want %v", tier, got, want)
		}
	}
}

func TestExposureMultiplier_MatchesDocumentedTable(t *testing.T) {
	cases := map[ExposureTier]float64{ExposureInternal: 0.60, ExposureRestricted: 0.75, ExposureInternetFacing: 1.00, ExposureUnknown: 0.70}
	for tier, want := range cases {
		got := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: tier}).ExposureMultiplier
		if got != want {
			t.Errorf("exposure multiplier for %s = %v, want %v", tier, got, want)
		}
	}
}

// --- Formula -----------------------------------------------------------

func TestFormula_ExactExample(t *testing.T) {
	// severity=HIGH(70) x confidence=HIGH(1.00) x verification=VERIFIED(1.00) x exposure=INTERNET_FACING(1.00) = 70.
	// 70 falls in the documented MEDIUM band (50-74) -- HIGH severity's
	// own ceiling under the suggested weight table is 70, one point
	// short of the HIGH priority band's floor (75). See
	// docs/phase-3-9-risk-scoring.md "Reachability" for why this is a
	// documented, deliberate characteristic of the suggested baseline
	// model (only CRITICAL severity, at 90, can reach the CRITICAL
	// priority band on its own), not a bug.
	b := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing})
	if b.RawScore != 70 {
		t.Errorf("RawScore = %v, want 70", b.RawScore)
	}
	if b.RiskScore != 70 {
		t.Errorf("RiskScore = %d, want 70", b.RiskScore)
	}
	if b.Priority != PriorityMedium {
		t.Errorf("Priority = %s, want MEDIUM (70 falls in the 50-74 band)", b.Priority)
	}
}

func TestFormula_CriticalMaximum(t *testing.T) {
	// severity=CRITICAL(90) x 1.00 x 1.00 x 1.00 = 90 -- the maximum this
	// formula's documented weight table can ever produce.
	b := Score(RiskFactors{Severity: models.SeverityCritical, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing})
	if b.RiskScore != 90 {
		t.Errorf("RiskScore = %d, want 90", b.RiskScore)
	}
	if b.Priority != PriorityCritical {
		t.Errorf("Priority = %s, want CRITICAL", b.Priority)
	}
}

func TestFormula_LowestCombination(t *testing.T) {
	b := Score(RiskFactors{Severity: models.SeverityLow, Confidence: ConfidenceLow, Verification: VerificationUnverified, Exposure: ExposureInternal})
	// 20 x 0.5 x 0.7 x 0.6 = 4.2 -> rounds to 4
	if b.RiskScore != 4 {
		t.Errorf("RiskScore = %d, want 4 (20*0.5*0.7*0.6=4.2)", b.RiskScore)
	}
	if b.Priority != PriorityLow {
		t.Errorf("Priority = %s, want LOW", b.Priority)
	}
}

// --- Rounding ------------------------------------------------------------

func TestRounding_HalfAwayFromZero(t *testing.T) {
	cases := []struct {
		raw  float64
		want int
	}{
		{4.5, 5}, {4.4, 4}, {4.6, 5}, {0.5, 1}, {0.4, 0}, {99.5, 100}, {89.5, 90},
	}
	for _, c := range cases {
		if got := clampScore(c.raw); got != c.want {
			t.Errorf("clampScore(%v) = %d, want %d", c.raw, got, c.want)
		}
	}
}

// --- Clamping ------------------------------------------------------------

func TestClamping_AboveMaximum(t *testing.T) {
	if got := clampScore(150); got != 100 {
		t.Errorf("clampScore(150) = %d, want 100", got)
	}
}

func TestClamping_BelowMinimum(t *testing.T) {
	if got := clampScore(-50); got != 0 {
		t.Errorf("clampScore(-50) = %d, want 0", got)
	}
}

func TestClamping_NaN(t *testing.T) {
	if got := clampScore(math.NaN()); got != 0 {
		t.Errorf("clampScore(NaN) = %d, want 0", got)
	}
}

func TestClamping_PositiveInfinity(t *testing.T) {
	if got := clampScore(math.Inf(1)); got != 100 {
		t.Errorf("clampScore(+Inf) = %d, want 100", got)
	}
}

func TestClamping_NegativeInfinity(t *testing.T) {
	if got := clampScore(math.Inf(-1)); got != 0 {
		t.Errorf("clampScore(-Inf) = %d, want 0", got)
	}
}

// --- Priority bands (task section 21's boundary tests) ---------------------

func TestPriorityBands_ExactBoundaries(t *testing.T) {
	cases := map[int]Priority{
		0: PriorityLow, 1: PriorityLow, 49: PriorityLow,
		50: PriorityMedium, 74: PriorityMedium,
		75: PriorityHigh, 89: PriorityHigh,
		90: PriorityCritical, 99: PriorityCritical, 100: PriorityCritical,
	}
	for score, want := range cases {
		if got := PriorityForScore(score); got != want {
			t.Errorf("PriorityForScore(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestPriorityBands_OutOfRangeClampedDefensively(t *testing.T) {
	if got := PriorityForScore(101); got != PriorityCritical {
		t.Errorf("PriorityForScore(101) = %s, want CRITICAL (clamped to 100)", got)
	}
	if got := PriorityForScore(-5); got != PriorityLow {
		t.Errorf("PriorityForScore(-5) = %s, want LOW (clamped to 0)", got)
	}
}

// --- Unknown values (task section 20) ---------------------------------------

func TestUnknownSeverity_ConservativeScoreNeverPanics(t *testing.T) {
	b := Score(RiskFactors{Severity: models.Severity("not_a_real_severity"), Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing})
	if b.SeverityRecognized {
		t.Error("SeverityRecognized = true, want false for a garbage severity value")
	}
	if b.SeverityBase != unknownSeverityBase {
		t.Errorf("SeverityBase = %d, want %d (the conservative fallback)", b.SeverityBase, unknownSeverityBase)
	}
	// Must never be treated as the strongest value (CRITICAL=90).
	if b.SeverityBase >= severityBase[models.SeverityCritical] {
		t.Error("unknown severity must never be scored at or above CRITICAL's base")
	}
}

func TestUnknownConfidence_DefaultsToLow(t *testing.T) {
	b := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceTier("bogus"), Verification: VerificationVerified, Exposure: ExposureInternetFacing})
	if b.ConfidenceMultiplier != confidenceMultiplier[ConfidenceLow] {
		t.Errorf("ConfidenceMultiplier = %v, want %v (LOW fallback)", b.ConfidenceMultiplier, confidenceMultiplier[ConfidenceLow])
	}
}

func TestUnknownVerification_DefaultsToUnverified(t *testing.T) {
	b := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationTier("bogus"), Exposure: ExposureInternetFacing})
	if b.VerificationMultiplier != verificationMultiplier[VerificationUnverified] {
		t.Errorf("VerificationMultiplier = %v, want %v (UNVERIFIED fallback)", b.VerificationMultiplier, verificationMultiplier[VerificationUnverified])
	}
}

func TestUnknownExposure_DefaultsToUnknownMultiplier(t *testing.T) {
	b := Score(RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureTier("bogus")})
	if b.ExposureMultiplier != exposureMultiplier[ExposureUnknown] {
		t.Errorf("ExposureMultiplier = %v, want %v (UNKNOWN fallback)", b.ExposureMultiplier, exposureMultiplier[ExposureUnknown])
	}
}

func TestEmptyRiskFactors_NeverPanics(t *testing.T) {
	b := Score(RiskFactors{})
	if b.RiskScore < 0 || b.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", b.RiskScore)
	}
}
