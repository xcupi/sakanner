package risk

import (
	"fmt"
	"strings"

	"sakanner/pkg/models"
)

// Explain builds a deterministic, human-readable explanation from
// factors and breakdown alone -- task section 10. Pure string
// formatting over fixed, exhaustive lookup tables; no LLM, no
// randomness, no external call. The SAME (factors, breakdown) input
// always produces the byte-identical explanation string -- see
// explain_test.go's reproducibility check.
func Explain(factors RiskFactors, breakdown ScoreBreakdown) string {
	severityPhrase := severityPhraseOf(factors.Severity, breakdown.SeverityRecognized)
	confidencePhrase := strings.ToLower(string(factors.Confidence))
	verificationPhrase := verificationPhraseOf(factors.Verification)
	exposurePhrase := exposurePhraseOf(factors.Exposure)

	return fmt.Sprintf(
		"%s vulnerability with %s-confidence, %s evidence, on %s. Risk score %d/100 (%s priority).",
		severityPhrase, confidencePhrase, verificationPhrase, exposurePhrase,
		breakdown.RiskScore, strings.ToLower(string(breakdown.Priority)),
	)
}

func severityPhraseOf(s models.Severity, recognized bool) string {
	if !recognized {
		return "Unknown-severity"
	}
	switch s {
	case models.SeverityCritical:
		return "Critical-severity"
	case models.SeverityHigh:
		return "High-severity"
	case models.SeverityMedium:
		return "Medium-severity"
	case models.SeverityLow:
		return "Low-severity"
	case models.SeverityInfo:
		return "Informational-severity"
	default:
		return "Unknown-severity"
	}
}

func verificationPhraseOf(v VerificationTier) string {
	switch v {
	case VerificationVerified:
		return "verified"
	case VerificationSuspicious:
		return "suspicious (unconfirmed)"
	case VerificationUnverified:
		return "unverified"
	default:
		return "unverified"
	}
}

func exposurePhraseOf(e ExposureTier) string {
	switch e {
	case ExposureInternetFacing:
		return "an internet-facing asset"
	case ExposureRestricted:
		return "a restricted-access asset"
	case ExposureInternal:
		return "an internal-only asset"
	case ExposureUnknown:
		return "an asset of unknown exposure"
	default:
		return "an asset of unknown exposure"
	}
}
