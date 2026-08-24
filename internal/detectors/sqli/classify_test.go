package sqli

import (
	"testing"

	"sakanner/pkg/models"
)

func TestComputeSignals_ErrorSuppressedWhenBaselineAlreadyErrors(t *testing.T) {
	baseline := []byte("Database error: something went wrong processing your request.")
	errBody := []byte("Database error: something went wrong processing your request.")
	sig := computeSignals(baseline, errBody, []byte("same"), []byte("same"))
	if sig.errorFamily != "" {
		t.Errorf("errorFamily = %q, want empty -- baseline already showed the identical error, so the probe adds no new evidence", sig.errorFamily)
	}
}

func TestComputeSignals_ErrorDetectedWhenBaselineIsClean(t *testing.T) {
	baseline := []byte("results: alice")
	errBody := []byte("You have an error in your SQL syntax near ''''")
	sig := computeSignals(baseline, errBody, []byte("results: alice, bob, admin"), []byte("results: (none)"))
	if sig.errorFamily != "mysql" || !sig.errorIsSpecific {
		t.Errorf("errorFamily = %q, errorIsSpecific = %v, want mysql/true", sig.errorFamily, sig.errorIsSpecific)
	}
}

func TestComputeSignals_BooleanDiffTrue(t *testing.T) {
	sig := computeSignals([]byte("x"), []byte("x"), []byte("results: alice, bob, admin"), []byte("results: (none)"))
	if !sig.booleanDiff {
		t.Error("booleanDiff = false, want true -- true/false bodies are genuinely different")
	}
}

func TestComputeSignals_BooleanDiffFalseWhenIdentical(t *testing.T) {
	sig := computeSignals([]byte("x"), []byte("x"), []byte("results: (none)"), []byte("results: (none)"))
	if sig.booleanDiff {
		t.Error("booleanDiff = true, want false -- true/false bodies are identical")
	}
}

func TestComputeSignals_BooleanDiffFalseAfterNormalizingDynamicContent(t *testing.T) {
	trueBody := []byte("results: (none)\n<!-- request-id: 41 -->")
	falseBody := []byte("results: (none)\n<!-- request-id: 42 -->")
	sig := computeSignals([]byte("x"), []byte("x"), trueBody, falseBody)
	if sig.booleanDiff {
		t.Error("booleanDiff = true, want false -- the only raw difference is a dynamic counter, which normalization must erase")
	}
}

func TestClassify_ErrorSpecificAndBoolean_HighestConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "mysql", errorIsSpecific: true, booleanDiff: true})
	if !ok {
		t.Fatal("classify: want ok=true")
	}
	if tier.severity != models.SeverityCritical {
		t.Errorf("severity = %q, want critical", tier.severity)
	}
	if tier.confidence < 0.9 {
		t.Errorf("confidence = %v, want >= 0.9 (multiple consistent signals)", tier.confidence)
	}
}

func TestClassify_BooleanOnly_HighConfidence(t *testing.T) {
	tier, ok := classify(signals{booleanDiff: true})
	if !ok {
		t.Fatal("classify: want ok=true")
	}
	if tier.severity != models.SeverityCritical {
		t.Errorf("severity = %q, want critical", tier.severity)
	}
	if tier.confidence < 0.7 || tier.confidence >= 0.9 {
		t.Errorf("confidence = %v, want in [0.7, 0.9) -- a proven differential is strong evidence but not corroborated by an error signal", tier.confidence)
	}
}

func TestClassify_SpecificErrorOnly_MediumConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "postgresql", errorIsSpecific: true})
	if !ok {
		t.Fatal("classify: want ok=true")
	}
	if tier.severity != models.SeverityHigh {
		t.Errorf("severity = %q, want high", tier.severity)
	}
	if tier.confidence < 0.4 || tier.confidence >= 0.7 {
		t.Errorf("confidence = %v, want a medium value in [0.4, 0.7)", tier.confidence)
	}
}

func TestClassify_GenericErrorOnly_LowConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "generic", errorIsSpecific: false})
	if !ok {
		t.Fatal("classify: want ok=true")
	}
	if tier.severity != models.SeverityMedium {
		t.Errorf("severity = %q, want medium", tier.severity)
	}
	if tier.confidence >= 0.4 {
		t.Errorf("confidence = %v, want a low value (< 0.4)", tier.confidence)
	}
}

func TestClassify_NoSignals_NoFinding(t *testing.T) {
	_, ok := classify(signals{})
	if ok {
		t.Error("classify: want ok=false when no signal was observed")
	}
}

func TestClassify_HighConfidenceStrictlyGreaterThanMediumAndLow(t *testing.T) {
	high, _ := classify(signals{errorFamily: "mysql", errorIsSpecific: true, booleanDiff: true})
	booleanOnly, _ := classify(signals{booleanDiff: true})
	medium, _ := classify(signals{errorFamily: "postgresql", errorIsSpecific: true})
	low, _ := classify(signals{errorFamily: "generic"})

	if !(high.confidence > booleanOnly.confidence && booleanOnly.confidence > medium.confidence && medium.confidence > low.confidence) {
		t.Errorf("confidence ordering violated: high=%v booleanOnly=%v medium=%v low=%v", high.confidence, booleanOnly.confidence, medium.confidence, low.confidence)
	}
}

// Regression coverage for a real false positive found via the Phase
// 3.3 lab integration test (TestPhase3_3_SQLiDetector_MatchesGroundTruth):
// any endpoint that echoes its parameter back verbatim -- a
// reflected-XSS-shaped page, an open redirect's auto-generated "Found"
// body, a "page not found: X" message -- produced a false boolean
// differential purely because the true/false PAYLOAD TEXT itself
// differs, with no SQL logic involved at all. Fixed by stripPayload
// (normalize.go); these tests lock that fix in at the computeSignals
// level, and TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding
// (detector_test.go) locks it in end to end.

func TestComputeSignals_NoFalsePositiveWhenPayloadEchoedRaw(t *testing.T) {
	trueBody := []byte("page not found: " + trueProbePayload)
	falseBody := []byte("page not found: " + falseProbePayload)
	sig := computeSignals([]byte("page not found: 1"), []byte("page not found: '"), trueBody, falseBody)
	if sig.booleanDiff {
		t.Error("booleanDiff = true, want false -- the only difference is the echoed payload text itself, not application behavior")
	}
}

func TestComputeSignals_NoFalsePositiveWhenPayloadEchoedHTMLEscaped(t *testing.T) {
	trueBody := []byte("You searched for: 1&#39; OR &#39;1&#39;=&#39;1")
	falseBody := []byte("You searched for: 1&#39; AND &#39;1&#39;=&#39;2")
	sig := computeSignals([]byte("You searched for: 1"), []byte("You searched for: &#39;"), trueBody, falseBody)
	if sig.booleanDiff {
		t.Error("booleanDiff = true, want false -- the only difference is the HTML-entity-encoded echoed payload text, not application behavior")
	}
}

func TestComputeSignals_GenuineDifferenceStillDetectedAfterStripping(t *testing.T) {
	// The stripping fix must not mask a REAL differential: neither body
	// contains the payload text at all here (a genuine data-level
	// difference, exactly like the real /sqli/vulnerable fixture).
	sig := computeSignals([]byte("results: alice"), []byte("results: alice"), []byte("results: alice, bob, admin"), []byte("results: (none)"))
	if !sig.booleanDiff {
		t.Error("booleanDiff = false, want true -- this is a genuine data-level difference the stripping fix must not erase")
	}
}
