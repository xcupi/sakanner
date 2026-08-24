package risk

import (
	"math"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

func TestDeriveFactors_ConfidenceTierBoundaries(t *testing.T) {
	cases := map[float64]ConfidenceTier{
		0.0: ConfidenceLow, 0.39: ConfidenceLow,
		0.4: ConfidenceMedium, 0.74: ConfidenceMedium,
		0.75: ConfidenceHigh, 1.0: ConfidenceHigh,
	}
	for conf, want := range cases {
		if got := confidenceTierOf(conf); got != want {
			t.Errorf("confidenceTierOf(%v) = %s, want %s", conf, got, want)
		}
	}
}

func TestDeriveFactors_NaNConfidenceFallsBackToLow(t *testing.T) {
	if got := confidenceTierOf(math.NaN()); got != ConfidenceLow {
		t.Errorf("confidenceTierOf(NaN) = %s, want LOW (every comparison against NaN is false)", got)
	}
}

func TestDeriveFactors_VerifiedWhenConfirmedByCorrelation(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "sql_injection", models.SeverityHigh, 0.5, correlation.StatusConfirmed, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Verification != VerificationVerified {
		t.Errorf("Verification = %s, want VERIFIED (Status=CONFIRMED means 2+ independent evidence signatures)", got.Verification)
	}
}

func TestDeriveFactors_SuspiciousWhenNewAndHighConfidence(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "sql_injection", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Verification != VerificationSuspicious {
		t.Errorf("Verification = %s, want SUSPICIOUS (single strong observation, not yet independently corroborated)", got.Verification)
	}
}

func TestDeriveFactors_UnverifiedWhenNewAndLowConfidence(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "sql_injection", models.SeverityHigh, 0.2, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Verification != VerificationUnverified {
		t.Errorf("Verification = %s, want UNVERIFIED", got.Verification)
	}
}

func TestDeriveFactors_VerificationNeverInferredFromSeverityAlone(t *testing.T) {
	// A CRITICAL-severity finding with weak, uncorroborated evidence
	// must still be UNVERIFIED -- severity plays no role in
	// verification derivation at all (task section 7).
	cf := canonicalFinding("scan-1", "f1", "command_injection", models.SeverityCritical, 0.1, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Verification != VerificationUnverified {
		t.Errorf("Verification = %s, want UNVERIFIED regardless of CRITICAL severity", got.Verification)
	}
}

func TestDeriveFactors_ExposureDefaultsToUnknownWithoutContext(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "ssrf", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Exposure != ExposureUnknown {
		t.Errorf("Exposure = %s, want UNKNOWN when no AssetContext is supplied (never assume internet-facing)", got.Exposure)
	}
}

func TestDeriveFactors_ExposureUsesSuppliedContext(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "ssrf", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, &AssetContext{Exposure: ExposureInternetFacing})
	if got.Exposure != ExposureInternetFacing {
		t.Errorf("Exposure = %s, want INTERNET_FACING", got.Exposure)
	}
}

func TestDeriveFactors_SeverityPassedThroughUnmodified(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "ssrf", models.SeverityCritical, 0.9, correlation.StatusNew, "h.test")
	got := DeriveFactors(cf, nil)
	if got.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical, unmodified", got.Severity)
	}
}
