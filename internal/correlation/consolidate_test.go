package correlation

import (
	"testing"

	"sakanner/pkg/models"
)

// Confidence values chosen to land cleanly in each of confidenceTier's
// buckets (LOW < 0.4 <= MEDIUM < 0.75 <= HIGH).
const (
	confLow    = 0.2
	confMedium = 0.55
	confHigh   = 0.9
)

func withConfidenceAndEvidence(f models.Finding, confidence float64, evidenceContent string) models.Finding {
	f.Confidence = confidence
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, evidenceContent)}
	return f
}

// --- Confidence consolidation (task sections 10, 27) ------------------------

func TestConfidence_LowPlusLow(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "evidence-A"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "evidence-B"),
	)
	got := e.Findings()[0]
	if tier := confidenceTier(got.Confidence); tier != "LOW" {
		t.Errorf("tier = %s (confidence=%v), want LOW", tier, got.Confidence)
	}
}

func TestConfidence_LowPlusMedium(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "evidence-A"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confMedium, "evidence-B"),
	)
	got := e.Findings()[0]
	if tier := confidenceTier(got.Confidence); tier != "MEDIUM" {
		t.Errorf("tier = %s (confidence=%v), want MEDIUM", tier, got.Confidence)
	}
}

func TestConfidence_MediumPlusHigh(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confMedium, "evidence-A"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "evidence-B"),
	)
	got := e.Findings()[0]
	if tier := confidenceTier(got.Confidence); tier != "HIGH" {
		t.Errorf("tier = %s (confidence=%v), want HIGH", tier, got.Confidence)
	}
}

func TestConfidence_HighPlusHigh(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "evidence-A"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "evidence-B"),
	)
	got := e.Findings()[0]
	if tier := confidenceTier(got.Confidence); tier != "HIGH" {
		t.Errorf("tier = %s (confidence=%v), want HIGH", tier, got.Confidence)
	}
}

func TestConfidence_RepeatedIdenticalEvidenceNeverIncreasesConfidence(t *testing.T) {
	// The SAME evidence content resubmitted with a HIGHER claimed
	// confidence must not be allowed to raise the canonical value --
	// the repeat is treated as the identical observation, and the
	// weakest claim about it wins (min-within-signature).
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "identical-evidence"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "identical-evidence"),
	)
	got := e.Findings()[0]
	if got.Confidence != confLow {
		t.Errorf("Confidence = %v, want %v (repeated identical evidence must not raise confidence)", got.Confidence, confLow)
	}
}

func TestConfidence_RepeatedIdenticalEvidenceOrderIndependent(t *testing.T) {
	// Same scenario as above, submitted in the opposite order -- the
	// result must be identical regardless of arrival order (task
	// section 32's determinism-under-concurrency requirement).
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "identical-evidence"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "identical-evidence"),
	)
	got := e.Findings()[0]
	if got.Confidence != confLow {
		t.Errorf("Confidence = %v, want %v regardless of arrival order", got.Confidence, confLow)
	}
}

func TestConfidence_IndependentEvidenceCanRaiseToHigh(t *testing.T) {
	// A genuinely NEW, independent piece of evidence establishing HIGH
	// confidence DOES raise the canonical finding, per task section 10.
	e := NewEngine()
	e.Ingest(withConfidenceAndEvidence(sqliFinding("scan-1", ""), confLow, "weak-evidence"))
	before := e.Findings()[0]
	if before.Confidence != confLow {
		t.Fatalf("before.Confidence = %v, want %v", before.Confidence, confLow)
	}

	e.Ingest(withConfidenceAndEvidence(sqliFinding("scan-1", ""), confHigh, "strong-independent-evidence"))
	after := e.Findings()[0]
	if after.Confidence != confHigh {
		t.Errorf("after.Confidence = %v, want %v (independent HIGH-confidence evidence must raise it)", after.Confidence, confHigh)
	}
}

// --- Severity consolidation (task sections 11, 28) --------------------------

func withSeverityAndEvidence(f models.Finding, sev models.Severity, evidenceContent string) models.Finding {
	f.Severity = sev
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, evidenceContent)}
	return f
}

func TestSeverity_LowPlusMedium(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityLow, "evidence-A"),
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityMedium, "evidence-B"),
	)
	got := e.Findings()[0]
	if got.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium", got.Severity)
	}
}

func TestSeverity_MediumPlusHigh(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityMedium, "evidence-A"),
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityHigh, "evidence-B"),
	)
	got := e.Findings()[0]
	if got.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", got.Severity)
	}
}

func TestSeverity_RepeatedIdenticalEvidenceDoesNotUpgrade(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityLow, "identical-evidence"),
		withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityCritical, "identical-evidence"),
	)
	got := e.Findings()[0]
	if got.Severity != models.SeverityLow {
		t.Errorf("Severity = %q, want low (repeated identical evidence must not upgrade severity)", got.Severity)
	}
}

func TestSeverity_NeverArbitrarilyUpgraded(t *testing.T) {
	// A single LOW-severity finding, ingested repeatedly, must stay LOW
	// -- merging must never invent a higher severity than any
	// contributing evidence actually supports.
	e := NewEngine()
	for i := 0; i < 5; i++ {
		e.Ingest(withSeverityAndEvidence(sqliFinding("scan-1", ""), models.SeverityLow, "same-evidence-every-time"))
	}
	got := e.Findings()[0]
	if got.Severity != models.SeverityLow {
		t.Errorf("Severity = %q, want low", got.Severity)
	}
}

// --- Status (task section 12) -----------------------------------------------

func TestStatus_NewForSingleEvidenceSignature(t *testing.T) {
	e := NewEngine()
	e.Ingest(sqliFinding("scan-1", ""))
	got := e.Findings()[0]
	if got.Status != StatusNew {
		t.Errorf("Status = %q, want NEW", got.Status)
	}
}

func TestStatus_ConfirmedForTwoDistinctEvidenceSignatures(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confMedium, "evidence-A"),
		withConfidenceAndEvidence(sqliFinding("scan-1", ""), confMedium, "evidence-B"),
	)
	got := e.Findings()[0]
	if got.Status != StatusConfirmed {
		t.Errorf("Status = %q, want CONFIRMED", got.Status)
	}
}

func TestStatus_RepeatedIdenticalSubmissionStaysNew(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 5; i++ {
		e.Ingest(withConfidenceAndEvidence(sqliFinding("scan-1", ""), confMedium, "same-evidence"))
	}
	got := e.Findings()[0]
	if got.Status != StatusNew {
		t.Errorf("Status = %q, want NEW (5 identical resubmissions is still only 1 distinct signature)", got.Status)
	}
}
