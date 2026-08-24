package sqliactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed signal set --
// evidence built exclusively via detection.MutationEvidence (Phase
// 3.17/3.19's relocated bridge), never a second, SQLi-specific
// evidence shape. Only the fields a detector is expected to set are
// populated here -- DetectorID/Host/Port/URL/Method/AffectedEndpoint/
// IdentityContext/ScanID/Source/timestamps are filled by the engine's
// normalizeFinding (Phase 3.1/3.19), which never overwrites what's
// already set here.
func (d Detector) finding(t detection.Target, sig signals, tier confidenceTier, baseline, errProbe, trueProbe, falseProbe probeResult) models.Finding {
	signalDesc := "boolean differential"
	if sig.errorFamily != "" {
		signalDesc = fmt.Sprintf("%s (error family: %s)", signalDesc, sig.errorFamily)
		if !sig.booleanDiff {
			signalDesc = fmt.Sprintf("database error (family: %s)", sig.errorFamily)
		}
	}

	return models.Finding{
		VulnerabilityType: "sql_injection",
		Title:             "SQL Injection (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s appears to reach a SQL query without adequate sanitization, based on active mutation-based probing (%s). This may allow an attacker to alter query logic, bypass application checks, or access data outside the intended scope.",
			t.Parameter, t.Path, signalDesc,
		),
		Severity:          tier.severity,
		Confidence:        tier.confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Use parameterized queries / prepared statements (or an ORM that does so) for every database query built from user input. Never concatenate untrusted input directly into SQL. Apply least-privilege database credentials and disable verbose database error output in production responses.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
				"a plain, syntactically inert control value establishes what a normal, non-malicious request to this parameter looks like, so the probes below can be judged against it rather than in isolation",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				errProbe.request, errProbe.response, &errProbe.mutation,
				fmt.Sprintf("baseline_status=%d error_probe_status=%d true_probe_status=%d false_probe_status=%d error_family=%q boolean_differential=%v",
					baseline.response.StatusCode, errProbe.response.StatusCode, trueProbe.response.StatusCode, falseProbe.response.StatusCode, sig.errorFamily, sig.booleanDiff),
				tier.reason,
			)),
		},
	}
}
