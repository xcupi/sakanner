// Ground-truth comparison infrastructure for Phase 3.
//
// IMPORTANT: no vulnerability detector exists in sakanner yet. This file
// does not implement one, simulate one, or claim one works. It builds
// the MACHINERY a future Phase 3 detector's own tests will need --
// comparing whatever real []models.Finding rows a real scan produces
// against this lab's ground truth, and classifying each as a true
// positive, false positive, false negative, or duplicate. Today, with
// no detector populating the Findings table, that machinery correctly
// reports "0 actual, N expected, N false negatives" -- which is the
// honest, correct answer, not a placeholder. See phase3_lab_test.go for
// how this is exercised against a real (currently empty) scan result,
// and comparison_test.go for proof the classification logic itself is
// correct, using synthetic actual-finding data.
package lab

import "sakanner/pkg/models"

// MatchStatus classifies one ground-truth finding or one actual finding
// after comparison.
type MatchStatus string

const (
	StatusTruePositive  MatchStatus = "true_positive"
	StatusFalsePositive MatchStatus = "false_positive"
	StatusFalseNegative MatchStatus = "false_negative"
	StatusDuplicate     MatchStatus = "duplicate"
)

// MatchResult is one row of the comparison: either an expected finding
// that was (or wasn't) found, or an actual finding that wasn't expected
// (or duplicates one already matched).
type MatchResult struct {
	Status MatchStatus

	// Expected is set for true_positive and false_negative rows.
	Expected *VulnFinding
	// Actual is set for true_positive, false_positive, and duplicate rows.
	Actual *models.Finding

	// SeverityMatches/EndpointMatches/EvidenceMatches are only
	// meaningful for true_positive rows -- they record whether the
	// MATCHED finding also got the finer-grained details right, per the
	// task's explicit ask to validate severity, endpoint attribution,
	// and evidence quality, not just presence/absence.
	SeverityMatches bool
	EndpointMatches bool
	EvidenceMatches bool
}

// ComparisonReport is the full expected-vs-actual comparison for one
// scan job against the Phase 3 ground truth.
type ComparisonReport struct {
	Results []MatchResult

	TotalExpected  int
	TotalActual    int
	TruePositives  int
	FalsePositives int
	FalseNegatives int
	Duplicates     int
}

// CompareFindings matches actual (real Finding rows from a Store, e.g.
// via store.Findings().ListByScanJob) against expected (this lab's
// positive ground-truth fixtures -- gt.Positives()). A match is a
// finding whose VulnerabilityType equals the ground truth's Type AND
// whose AffectedEndpoint equals the ground truth's Endpoint (a stricter
// key, e.g. also requiring the exact parameter, would be reasonable once
// a real detector exists to calibrate against; this starting point
// mirrors how a human triager would first group findings).
//
// negatives (gt.Negatives()) are used to flag a special, higher-severity
// case: an actual finding whose endpoint matches a NEGATIVE (safe)
// fixture is a confirmed false positive on a fixture specifically
// engineered to prove the detector doesn't over-fire -- see
// MatchResult.Actual for those rows (Status: false_positive).
func CompareFindings(actual []models.Finding, positives []VulnFinding, negatives []VulnFinding) ComparisonReport {
	var report ComparisonReport
	report.TotalExpected = len(positives)
	report.TotalActual = len(actual)

	matchedExpected := make(map[string]bool, len(positives)) // by VulnFinding.ID
	matchedActualIdx := make(map[int]bool, len(actual))

	// First pass: for each actual finding, find the first not-yet-matched
	// expected positive it corresponds to.
	for i := range actual {
		a := &actual[i]
		matched := false
		for _, exp := range positives {
			if matchedExpected[exp.ID] {
				continue
			}
			if findingMatchesExpected(a, &exp) {
				matchedExpected[exp.ID] = true
				matchedActualIdx[i] = true
				result := MatchResult{
					Status:          StatusTruePositive,
					Expected:        &exp,
					Actual:          a,
					SeverityMatches: string(a.Severity) == exp.Severity,
					EndpointMatches: a.AffectedEndpoint == exp.Endpoint,
					EvidenceMatches: evidenceLooksPresent(a, &exp),
				}
				report.Results = append(report.Results, result)
				report.TruePositives++
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// Not matched to any expected positive -- either it duplicates an
		// actual finding already claimed for the same expected ID, a
		// false positive against a known-safe (negative) fixture, or a
		// false positive against nothing in ground truth at all.
		if dupOf := findDuplicateOf(a, actual, matchedActualIdx, i); dupOf != nil {
			report.Results = append(report.Results, MatchResult{Status: StatusDuplicate, Actual: a})
			report.Duplicates++
			continue
		}

		report.Results = append(report.Results, MatchResult{Status: StatusFalsePositive, Actual: a})
		report.FalsePositives++
	}

	// Second pass: every expected positive never matched is a false
	// negative.
	for _, exp := range positives {
		exp := exp
		if !matchedExpected[exp.ID] {
			report.Results = append(report.Results, MatchResult{Status: StatusFalseNegative, Expected: &exp})
			report.FalseNegatives++
		}
	}

	_ = negatives // reserved for a stricter check once a real detector exists to calibrate against; see docs/phase-3-test-lab.md
	return report
}

// findingMatchesExpected is intentionally a loose match (type + endpoint)
// -- see CompareFindings' doc comment for why.
func findingMatchesExpected(a *models.Finding, exp *VulnFinding) bool {
	return a.VulnerabilityType == exp.Type && a.AffectedEndpoint == exp.Endpoint
}

// evidenceLooksPresent is a minimal, honest check: does this finding
// carry ANY evidence at all. It does not (cannot, without a real
// detector to calibrate against) verify the evidence's CONTENT matches
// ExpectedEvidence precisely -- that calibration belongs to Phase 3's
// own test suite, once it exists.
func evidenceLooksPresent(a *models.Finding, exp *VulnFinding) bool {
	if len(a.Evidence) > 0 {
		return true
	}
	return false
}

// findDuplicateOf reports whether actual[i] duplicates an earlier
// already-matched (to the same expected finding) actual result, by
// (VulnerabilityType, AffectedEndpoint, AffectedParameter) equality
// against any OTHER already-processed actual finding.
func findDuplicateOf(a *models.Finding, actual []models.Finding, matched map[int]bool, i int) *models.Finding {
	for j := 0; j < i; j++ {
		if !matched[j] {
			continue
		}
		b := &actual[j]
		if a.VulnerabilityType == b.VulnerabilityType && a.AffectedEndpoint == b.AffectedEndpoint && a.AffectedParameter == b.AffectedParameter {
			return b
		}
	}
	return nil
}
