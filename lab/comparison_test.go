package lab

import (
	"testing"

	"sakanner/pkg/models"
)

// These tests use hand-built, synthetic []models.Finding data -- NOT
// output from a real detector, since none exists yet -- specifically to
// prove CompareFindings' classification logic itself is correct. Once a
// real Phase 3 detector exists, the exact same function, unchanged,
// should classify its real output correctly too.

func testPositives() []VulnFinding {
	return []VulnFinding{
		{ID: "V1", Type: "reflected_xss", Endpoint: "/xss/reflected/vulnerable", Severity: "high"},
		{ID: "V2", Type: "sql_injection", Endpoint: "/sqli/vulnerable", Severity: "critical"},
		{ID: "V3", Type: "open_redirect", Endpoint: "/redirect/open/vulnerable", Severity: "medium"},
	}
}

func TestCompareFindings_NoActualFindings_AllFalseNegatives(t *testing.T) {
	report := CompareFindings(nil, testPositives(), nil)

	if report.TotalExpected != 3 {
		t.Errorf("TotalExpected = %d, want 3", report.TotalExpected)
	}
	if report.TotalActual != 0 {
		t.Errorf("TotalActual = %d, want 0", report.TotalActual)
	}
	if report.TruePositives != 0 || report.FalsePositives != 0 || report.Duplicates != 0 {
		t.Errorf("expected 0 TP/FP/Duplicate with no actual findings, got TP=%d FP=%d Dup=%d", report.TruePositives, report.FalsePositives, report.Duplicates)
	}
	if report.FalseNegatives != 3 {
		t.Errorf("FalseNegatives = %d, want 3 (every expected finding, since nothing was found)", report.FalseNegatives)
	}
}

func TestCompareFindings_ExactMatch_IsTruePositive(t *testing.T) {
	actual := []models.Finding{
		{
			ID: "f1", VulnerabilityType: "reflected_xss", AffectedEndpoint: "/xss/reflected/vulnerable",
			Severity: models.SeverityHigh, Evidence: []models.Evidence{{ID: "e1", Kind: models.EvidenceKindText, Content: "reflected payload"}},
		},
	}
	report := CompareFindings(actual, testPositives(), nil)

	if report.TruePositives != 1 {
		t.Fatalf("TruePositives = %d, want 1", report.TruePositives)
	}
	if report.FalseNegatives != 2 {
		t.Errorf("FalseNegatives = %d, want 2 (the other two expected findings)", report.FalseNegatives)
	}
	if report.FalsePositives != 0 || report.Duplicates != 0 {
		t.Errorf("expected 0 FP/Duplicate, got FP=%d Dup=%d", report.FalsePositives, report.Duplicates)
	}

	var tp *MatchResult
	for i := range report.Results {
		if report.Results[i].Status == StatusTruePositive {
			tp = &report.Results[i]
		}
	}
	if tp == nil {
		t.Fatal("no true_positive result found")
	}
	if !tp.SeverityMatches {
		t.Error("SeverityMatches = false, want true (both say high)")
	}
	if !tp.EndpointMatches {
		t.Error("EndpointMatches = false, want true (identical endpoint strings)")
	}
	if !tp.EvidenceMatches {
		t.Error("EvidenceMatches = false, want true (Evidence slice is non-empty)")
	}
}

func TestCompareFindings_UnexpectedFinding_IsFalsePositive(t *testing.T) {
	actual := []models.Finding{
		{ID: "f1", VulnerabilityType: "reflected_xss", AffectedEndpoint: "/xss/reflected/safe"}, // the SAFE fixture -- ground truth has no positive entry for this endpoint
	}
	report := CompareFindings(actual, testPositives(), nil)

	if report.FalsePositives != 1 {
		t.Fatalf("FalsePositives = %d, want 1 (a finding on a fixture with no matching positive ground truth)", report.FalsePositives)
	}
	if report.TruePositives != 0 {
		t.Errorf("TruePositives = %d, want 0", report.TruePositives)
	}
	if report.FalseNegatives != 3 {
		t.Errorf("FalseNegatives = %d, want 3 (all three real positives are still unfound)", report.FalseNegatives)
	}
}

func TestCompareFindings_RepeatedFinding_IsDuplicate(t *testing.T) {
	actual := []models.Finding{
		{ID: "f1", VulnerabilityType: "reflected_xss", AffectedEndpoint: "/xss/reflected/vulnerable", Severity: models.SeverityHigh},
		{ID: "f2", VulnerabilityType: "reflected_xss", AffectedEndpoint: "/xss/reflected/vulnerable", Severity: models.SeverityHigh}, // same type+endpoint+parameter as f1
	}
	report := CompareFindings(actual, testPositives(), nil)

	if report.TruePositives != 1 {
		t.Errorf("TruePositives = %d, want 1 (only the first occurrence counts as the match)", report.TruePositives)
	}
	if report.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1 (the second, repeated finding)", report.Duplicates)
	}
	if report.FalsePositives != 0 {
		t.Errorf("FalsePositives = %d, want 0 -- a duplicate is not the same thing as a false positive", report.FalsePositives)
	}
}

func TestCompareFindings_SeverityMismatchIsFlagged(t *testing.T) {
	actual := []models.Finding{
		{ID: "f1", VulnerabilityType: "sql_injection", AffectedEndpoint: "/sqli/vulnerable", Severity: models.SeverityLow}, // ground truth says critical
	}
	report := CompareFindings(actual, testPositives(), nil)

	if report.TruePositives != 1 {
		t.Fatalf("TruePositives = %d, want 1 (type+endpoint still match)", report.TruePositives)
	}
	var tp *MatchResult
	for i := range report.Results {
		if report.Results[i].Status == StatusTruePositive {
			tp = &report.Results[i]
		}
	}
	if tp.SeverityMatches {
		t.Error("SeverityMatches = true, want false (low != critical) -- a true positive can still have a wrong severity, and that must be visible, not silently ignored")
	}
}

func TestCompareFindings_EmptyGroundTruthWithActualFindings_AllFalsePositive(t *testing.T) {
	actual := []models.Finding{
		{ID: "f1", VulnerabilityType: "reflected_xss", AffectedEndpoint: "/xss/reflected/vulnerable"},
	}
	report := CompareFindings(actual, nil, nil)

	if report.FalsePositives != 1 {
		t.Errorf("FalsePositives = %d, want 1", report.FalsePositives)
	}
	if report.TotalExpected != 0 {
		t.Errorf("TotalExpected = %d, want 0", report.TotalExpected)
	}
}

// TestLoadVulnGroundTruth_MatchesRealFixtures is the bridge between the
// synthetic-data tests above and the real lab: it loads the real ground
// truth file and confirms its shape is exactly what the harness
// fixtures (harness_vuln.go) actually implement -- 17 vulnerability
// classes, one positive and one negative fixture each.
func TestLoadVulnGroundTruth_MatchesRealFixtures(t *testing.T) {
	gt, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}
	if gt.Host != "vuln.scanner.test" {
		t.Errorf("Host = %q, want vuln.scanner.test", gt.Host)
	}
	if gt.InternalHost != "ssrf-internal.scanner.test" {
		t.Errorf("InternalHost = %q, want ssrf-internal.scanner.test", gt.InternalHost)
	}
	positives := gt.Positives()
	negatives := gt.Negatives()
	// 17 vulnerability classes (one positive each) + 1 Phase 3.2 addition
	// (attribute-context reflected XSS) + 1 Phase 3.3 addition
	// (boolean-only SQLi) + 1 Phase 3.5 addition (query-parameter IDOR)
	// + 1 Phase 3.6 addition (query-parameter path traversal) + 1 Phase
	// 3.7 addition (command injection) + 1 Phase 3.25 addition
	// (VULN-SSRF-BLIND-001, a genuinely distinct blind/OOB-only positive
	// -- see docs/phase-3-25-ssrf-active-detection.md) + 1 Phase 3.26
	// addition (VULN-CMDI-API-WINDOWS-001, a genuinely distinct
	// Windows-cmd.exe-style positive -- see
	// docs/phase-3-26-command-injection-active.md) = 24 positives
	// (Phase 3.4 added no new positive -- VULN-SSRF-001 already covered
	// its need). 17 safe counterparts + 3 Phase 3.2 + 3 Phase 3.3 + 4
	// Phase 3.4 + 4 Phase 3.5 + 7 Phase 3.6 + 7 Phase 3.7 = 45 negatives
	// (Phase 3.25/3.26 added no new negative). See
	// ground-truth-vulnerabilities.yaml's "Phase 3.2/3.3/3.4/3.5/3.6/3.7/3.25/3.26
	// additions" comments.
	if len(positives) != 24 {
		t.Errorf("len(Positives()) = %d, want 24 (17 vulnerability classes + 1 Phase 3.2 + 1 Phase 3.3 + 1 Phase 3.5 + 1 Phase 3.6 + 1 Phase 3.7 + 1 Phase 3.25 + 1 Phase 3.26)", len(positives))
	}
	if len(negatives) != 45 {
		t.Errorf("len(Negatives()) = %d, want 45 (17 safe counterparts + 3 Phase 3.2 + 3 Phase 3.3 + 4 Phase 3.4 + 4 Phase 3.5 + 7 Phase 3.6 + 7 Phase 3.7 negatives)", len(negatives))
	}

	seen := map[string]bool{}
	for _, f := range gt.Findings {
		if seen[f.ID] {
			t.Errorf("duplicate finding ID in ground truth: %s", f.ID)
		}
		seen[f.ID] = true
		if f.Type == "" || f.Endpoint == "" || f.Host == "" {
			t.Errorf("finding %s is missing a required field: %+v", f.ID, f)
		}
		if !f.Negative && f.Severity == "" {
			t.Errorf("positive finding %s has no severity", f.ID)
		}
		if !f.Negative && !isKnownSeverity(f.Severity) {
			t.Errorf("finding %s has severity %q, not one of pkg/models.Severity's known values", f.ID, f.Severity)
		}
	}
}

func isKnownSeverity(s string) bool {
	switch models.Severity(s) {
	case models.SeverityInfo, models.SeverityLow, models.SeverityMedium, models.SeverityHigh, models.SeverityCritical:
		return true
	}
	return false
}
