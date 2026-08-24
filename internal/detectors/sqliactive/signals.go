package sqliactive

import (
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// signals is the correlated evidence gathered from one candidate's 4
// probes, computed once and then mapped to a confidence/severity tier
// by classify -- kept as a separate, directly-testable struct so
// confidence calculation can be unit-tested against synthetic inputs
// without needing an HTTP server (mirrors
// internal/detectors/sqli's own established structure).
type signals struct {
	errorFamily     string // "" if no database error signature matched anywhere relevant
	errorIsSpecific bool   // true if errorFamily is a named DB family, not just "generic"
	booleanDiff     bool   // true/false probes produced meaningfully different (normalized, payload-stripped) responses
}

// computeSignals correlates the 4 probe responses. The error signal is
// correlated against the BASELINE before being trusted: an endpoint
// that already shows database-error-shaped text for a plain, benign
// request (task section 9's "generic HTTP 500"/"unrelated database
// error" cases -- the lab's own /sqli/generic-error fixture is
// UNCONDITIONAL, so its baseline probe already matches) gives the
// error probe's own matching text zero additional weight.
//
// The boolean signal compares the true/false probe bodies AFTER
// stripping each probe's own payload text (raw/HTML-encoded/URL-
// encoded) and normalizing via mutation.Compare -- see detector.go's
// stripPayload and docs/phase-3-20-sqli.md section 2.
func computeSignals(baseline, errProbe, trueProbe, falseProbe probeResult) signals {
	baselineFamily, baselineMatched := matchDBError(string(baseline.response.Body))
	errFamily, errMatched := matchDBError(string(errProbe.response.Body))

	var sig signals
	if errMatched && !(baselineMatched && baselineFamily == errFamily) {
		sig.errorFamily = errFamily
		sig.errorIsSpecific = errFamily != "generic"
	}

	trueStripped := stripPayload(trueProbe.response.Body, truePayload)
	falseStripped := stripPayload(falseProbe.response.Body, falsePayload)
	trueForCompare := trueProbe.response
	trueForCompare.Body = trueStripped
	trueForCompare.BodySize = int64(len(trueStripped))
	falseForCompare := falseProbe.response
	falseForCompare.Body = falseStripped
	falseForCompare.BodySize = int64(len(falseStripped))

	cmp := mutation.Compare(trueForCompare, falseForCompare)
	sig.booleanDiff = cmp.StructurallyDifferent || !cmp.BodyNormalizedIdentical
	return sig
}

// confidenceTier names a (severity, confidence, reason) triple for one
// signal combination -- the ONLY place this mapping is defined,
// mirroring internal/detectors/sqli's own established rubric exactly
// (Phase 3.3, independently re-derived here per detector-independence
// -- see docs/phase-3-20-sqli.md section 1 finding 9).
type confidenceTier struct {
	severity   models.Severity
	confidence float64
	reason     string
}

// classify maps correlated signals onto the HIGH/MEDIUM/LOW confidence
// rubric documented in docs/phase-3-20-sqli.md section 2, returning
// ok=false when there is insufficient evidence for any finding at all
// -- a single weak signal alone (a generic error, or a boolean
// difference with no error) never reaches Critical, and NO signal at
// all is always NoFinding, never a low-confidence guess (task
// section 9's own explicit "prefer no finding over a low-confidence
// false positive").
func classify(sig signals) (confidenceTier, bool) {
	switch {
	case sig.errorIsSpecific && sig.booleanDiff:
		return confidenceTier{models.SeverityCritical, 0.95, "a database-family-specific error signature AND a consistent boolean true/false differential were both observed -- multiple independent signals"}, true
	case sig.booleanDiff:
		return confidenceTier{models.SeverityCritical, 0.75, "a controlled true-condition and false-condition probe produced a consistent, meaningful behavioral difference (payload-stripped, normalized) -- confirmed data-exposure differential, independent of any error text"}, true
	case sig.errorIsSpecific:
		return confidenceTier{models.SeverityHigh, 0.55, "a " + sig.errorFamily + "-family database error signature was observed for the syntax-breaking probe but not for the baseline -- a strong indication, but the boolean differential probes did not independently confirm it"}, true
	case sig.errorFamily == "generic":
		return confidenceTier{models.SeverityMedium, 0.3, "only generic, cross-family database-error-shaped wording was observed, and the boolean differential probes did not confirm it -- a weak indication only"}, true
	default:
		return confidenceTier{}, false
	}
}
