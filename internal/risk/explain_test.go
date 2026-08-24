package risk

import (
	"strings"
	"testing"

	"sakanner/pkg/models"
)

func TestExplain_Reproducible(t *testing.T) {
	factors := RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing}
	breakdown := Score(factors)
	e1 := Explain(factors, breakdown)
	e2 := Explain(factors, breakdown)
	if e1 != e2 {
		t.Errorf("Explain not reproducible: %q vs %q", e1, e2)
	}
}

func TestExplain_MentionsSeverityConfidenceVerificationExposure(t *testing.T) {
	factors := RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing}
	breakdown := Score(factors)
	got := Explain(factors, breakdown)

	for _, want := range []string{"High-severity", "high-confidence", "verified", "internet-facing"} {
		if !strings.Contains(got, want) {
			t.Errorf("Explain() = %q, want it to contain %q", got, want)
		}
	}
}

func TestExplain_UnknownSeverityLabeled(t *testing.T) {
	factors := RiskFactors{Severity: models.Severity("garbage"), Confidence: ConfidenceLow, Verification: VerificationUnverified, Exposure: ExposureUnknown}
	breakdown := Score(factors)
	got := Explain(factors, breakdown)
	if !strings.Contains(got, "Unknown-severity") {
		t.Errorf("Explain() = %q, want it to mention Unknown-severity for an unrecognized severity value", got)
	}
}

func TestExplain_NeverEmpty(t *testing.T) {
	got := Explain(RiskFactors{}, Score(RiskFactors{}))
	if got == "" {
		t.Error("Explain(zero-value factors) is empty")
	}
}

func TestExplain_IncludesScoreAndPriority(t *testing.T) {
	factors := RiskFactors{Severity: models.SeverityCritical, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing}
	breakdown := Score(factors)
	got := Explain(factors, breakdown)
	if !strings.Contains(got, "90/100") {
		t.Errorf("Explain() = %q, want it to contain the numeric score 90/100", got)
	}
	if !strings.Contains(strings.ToLower(got), "critical priority") {
		t.Errorf("Explain() = %q, want it to contain the priority", got)
	}
}
