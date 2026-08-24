package sqliactive

import (
	"testing"

	"sakanner/internal/mutation"
)

func resp(status int, body string) probeResult {
	return probeResult{response: mutation.Response{StatusCode: status, Body: []byte(body), BodySize: int64(len(body))}}
}

func TestComputeSignals_ErrorFamilySpecific_BaselineClean(t *testing.T) {
	baseline := resp(200, "results: (none)")
	errProbe := resp(500, "you have an error in your SQL syntax near ''")
	trueProbe := resp(200, "results: (none)")
	falseProbe := resp(200, "results: (none)")

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	if sig.errorFamily != "mysql" || !sig.errorIsSpecific {
		t.Errorf("got errorFamily=%q errorIsSpecific=%v, want mysql/true", sig.errorFamily, sig.errorIsSpecific)
	}
	if sig.booleanDiff {
		t.Error("booleanDiff should be false when true/false probes are identical")
	}
}

func TestComputeSignals_ErrorAlreadyInBaseline_NoSignal(t *testing.T) {
	// The exact /sqli/generic-error shape: the SAME error text appears
	// in the baseline too, so it must never be trusted as a probe-
	// specific signal.
	errorText := "Database error: something went wrong processing your request."
	baseline := resp(500, errorText)
	errProbe := resp(500, errorText)
	trueProbe := resp(500, errorText)
	falseProbe := resp(500, errorText)

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	if sig.errorFamily != "" {
		t.Errorf("errorFamily = %q, want empty -- the error is unconditional, already present in baseline", sig.errorFamily)
	}
	if sig.booleanDiff {
		t.Error("booleanDiff should be false when true/false probes are identical")
	}
}

func TestComputeSignals_BooleanDifferential_NoErrorText(t *testing.T) {
	baseline := resp(200, "results: (none)")
	errProbe := resp(200, "results: (none)")
	trueProbe := resp(200, "results: alice, bob, admin")
	falseProbe := resp(200, "results: (none)")

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	if sig.errorFamily != "" {
		t.Errorf("errorFamily = %q, want empty (no error text anywhere)", sig.errorFamily)
	}
	if !sig.booleanDiff {
		t.Error("expected booleanDiff = true for genuinely different true/false bodies")
	}
}

func TestComputeSignals_ReflectedPayload_StrippedBeforeCompare(t *testing.T) {
	// Both probes reflect their OWN payload back verbatim, but the
	// MEANINGFUL content is otherwise identical -- after stripping,
	// there must be no boolean signal.
	baseline := resp(200, "you searched for: 1")
	errProbe := resp(200, "you searched for: '")
	trueProbe := resp(200, "you searched for: "+truePayload)
	falseProbe := resp(200, "you searched for: "+falsePayload)

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	if sig.booleanDiff {
		t.Error("SECURITY: a reflected-payload-only difference must not be reported as a boolean differential")
	}
}

func TestComputeSignals_DigitOnlyDifference_NoBooleanSignal(t *testing.T) {
	// mutation.Compare's own digit-run normalization means a purely
	// numeric difference (e.g. an incrementing request counter) is not
	// mistaken for a genuine boolean differential.
	baseline := resp(200, "results: (none) req=1")
	errProbe := resp(200, "results: (none) req=2")
	trueProbe := resp(200, "results: (none) req=3")
	falseProbe := resp(200, "results: (none) req=4")

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	if sig.booleanDiff {
		t.Error("a purely numeric difference (e.g. a request counter) must not be reported as a boolean differential")
	}
}

func TestClassify_BothSignals_CriticalHighestConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "mysql", errorIsSpecific: true, booleanDiff: true})
	if !ok || tier.severity != "critical" || tier.confidence != 0.95 {
		t.Errorf("got %+v ok=%v, want critical/0.95", tier, ok)
	}
}

func TestClassify_BooleanOnly_CriticalLowerConfidence(t *testing.T) {
	tier, ok := classify(signals{booleanDiff: true})
	if !ok || tier.severity != "critical" || tier.confidence != 0.75 {
		t.Errorf("got %+v ok=%v, want critical/0.75", tier, ok)
	}
}

func TestClassify_ErrorOnly_HighConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "postgresql", errorIsSpecific: true})
	if !ok || tier.severity != "high" || tier.confidence != 0.55 {
		t.Errorf("got %+v ok=%v, want high/0.55", tier, ok)
	}
}

func TestClassify_GenericErrorOnly_MediumLowConfidence(t *testing.T) {
	tier, ok := classify(signals{errorFamily: "generic"})
	if !ok || tier.severity != "medium" || tier.confidence != 0.3 {
		t.Errorf("got %+v ok=%v, want medium/0.3", tier, ok)
	}
}

func TestClassify_NoSignal_NotOK(t *testing.T) {
	_, ok := classify(signals{})
	if ok {
		t.Error("expected ok=false for a completely empty signal set -- never guess with no evidence")
	}
}

func TestMatchDBError_KnownFamilies(t *testing.T) {
	cases := map[string]string{
		"You have an error in your SQL syntax":        "mysql",
		"PostgreSQL query failed: ERROR":              "postgresql",
		"Unclosed quotation mark after the character": "mssql",
		`SQLite3::OperationalError: near "'"`:         "sqlite",
		"ORA-00933: SQL command not properly ended":   "oracle",
		"A generic SQL syntax problem occurred":       "generic",
	}
	for body, want := range cases {
		family, matched := matchDBError(body)
		if !matched || family != want {
			t.Errorf("matchDBError(%q) = (%q, %v), want (%q, true)", body, family, matched, want)
		}
	}
}

func TestMatchDBError_NoMatch(t *testing.T) {
	_, matched := matchDBError("results: (none)")
	if matched {
		t.Error("expected no match for ordinary, non-error content")
	}
}
