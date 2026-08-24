package risk

import (
	"sort"
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Assess scores one CanonicalFinding -- task section 2's pipeline
// stage (Detector → Phase 3.8 → CanonicalFinding → Phase 3.9 Risk
// Engine → Risk Assessment). ctx is optional (nil is valid) --
// task section 9's "support optional asset context."
func Assess(cf correlation.CanonicalFinding, ctx *AssetContext) Assessment {
	factors := DeriveFactors(cf, ctx)
	breakdown := Score(factors)
	return Assessment{
		FindingID:         cf.FindingID,
		ScanID:            cf.ScanID,
		VulnerabilityType: cf.VulnerabilityType,
		Severity:          cf.Severity,
		Factors:           factors,
		Breakdown:         breakdown,
		RiskScore:         breakdown.RiskScore,
		Priority:          breakdown.Priority,
		Explanation:       Explain(factors, breakdown),
		Asset:             assetSummaryOf(cf, ctx),
		AssessedAt:        time.Now().UTC(),
	}
}

// AssessAll scores every finding in findings, using ctxByFindingID to
// look up each one's optional AssetContext (a nil map, or a finding
// with no entry, both mean "no context" -- identical to passing nil
// directly to Assess). Findings from an EMPTY slice produce an empty
// (non-nil) result slice -- section 22's "empty finding set" case.
func AssessAll(findings []correlation.CanonicalFinding, ctxByFindingID map[string]*AssetContext) []Assessment {
	out := make([]Assessment, 0, len(findings))
	for _, cf := range findings {
		var ctx *AssetContext
		if ctxByFindingID != nil {
			ctx = ctxByFindingID[cf.FindingID]
		}
		out = append(out, Assess(cf, ctx))
	}
	return out
}

// severityRank orders pkg/models.Severity for the ranking tiebreak
// (task section 14, step 2) -- the same ordinal comparator
// internal/correlation's own rankOfSeverity uses, redefined here since
// this package deliberately does not import unexported symbols from
// internal/correlation (keeping the two packages independently
// testable and avoiding a cross-package coupling this phase's own
// "detector/package independence" principle argues against).
var severityRank = map[models.Severity]int{
	models.SeverityInfo:     0,
	models.SeverityLow:      1,
	models.SeverityMedium:   2,
	models.SeverityHigh:     3,
	models.SeverityCritical: 4,
}

func rankOfSeverity(s models.Severity) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

var confidenceRank = map[ConfidenceTier]int{
	ConfidenceLow: 0, ConfidenceMedium: 1, ConfidenceHigh: 2,
}

var verificationRank = map[VerificationTier]int{
	VerificationUnverified: 0, VerificationSuspicious: 1, VerificationVerified: 2,
}

// Rank sorts assessments deterministically -- task section 14's exact
// 8-step order: risk score desc, severity desc, confidence desc,
// verification desc, normalized host, normalized path, vulnerability
// type, finding ID. Ties at every step fall through to the next one;
// FindingID (a content hash, see docs/phase-3-8-finding-correlation.md)
// is always available and always sufficient as the final tiebreak, so
// this ordering is total -- two distinct assessments are never
// reported as equal. Rank does not mutate its input; it returns a new,
// sorted slice (task section 13's "adding unrelated findings must not
// change an existing finding's score" -- ranking is a pure read, never
// feeds back into scoring).
func Rank(assessments []Assessment) []Assessment {
	out := make([]Assessment, len(assessments))
	copy(out, assessments)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if ra, rb := rankOfSeverity(a.Severity), rankOfSeverity(b.Severity); ra != rb {
			return ra > rb
		}
		if ra, rb := confidenceRank[a.Factors.Confidence], confidenceRank[b.Factors.Confidence]; ra != rb {
			return ra > rb
		}
		if ra, rb := verificationRank[a.Factors.Verification], verificationRank[b.Factors.Verification]; ra != rb {
			return ra > rb
		}
		if a.Asset.Host != b.Asset.Host {
			return a.Asset.Host < b.Asset.Host
		}
		if a.Asset.Path != b.Asset.Path {
			return a.Asset.Path < b.Asset.Path
		}
		if a.VulnerabilityType != b.VulnerabilityType {
			return a.VulnerabilityType < b.VulnerabilityType
		}
		// FindingID (a content hash -- see
		// docs/phase-3-8-finding-correlation.md) is always available
		// and always distinguishes two genuinely different findings, so
		// it is the final, always-sufficient tiebreak -- task section
		// 14's step 8.
		return a.FindingID < b.FindingID
	})
	return out
}
