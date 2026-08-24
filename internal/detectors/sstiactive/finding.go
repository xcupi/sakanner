package sstiactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed SSTI -- evidence
// built exclusively via detection.MutationEvidence, never a second,
// detector-specific evidence shape. Only the fields a detector is
// expected to set are populated here -- DetectorID/Host/Port/URL/
// Method/AffectedEndpoint/IdentityContext/ScanID/Source/timestamps
// are filled by the engine's normalizeFinding, which never overwrites
// what's already set here.
func (d *Detector) finding(t detection.Target, variant templateVariant, a, b, product int, baseline, probe probeResult) models.Finding {
	reason := fmt.Sprintf(
		"the response contains %q -- the exact product of two operands (%d*%d) freshly chosen for this one probe -- which could only appear if the injected %s-style template expression (%q) was genuinely evaluated server-side, not merely reflected, a status code, or a generic response",
		fmt.Sprintf("%d", product), a, b, variant.name, variant.payload,
	)

	return models.Finding{
		VulnerabilityType: "ssti",
		Title:             "Server-Side Template Injection (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s evaluates a %s-style template expression (%s) server-side, confirmed by the exact arithmetic result (%d) appearing in the response.",
			t.Parameter, t.Path, variant.name, variant.payload, product,
		),
		Severity:          models.SeverityHigh,
		Confidence:        0.9,
		AffectedParameter: t.Parameter,
		Remediation:       "Never render user-controlled input through a template engine's own expression evaluator. Treat all user input as plain data (auto-escaped, non-executable) -- use a sandboxed/logic-less template mode where available, and never construct a template STRING from user input at all.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
				"the endpoint's own originally-discovered value, unmutated, establishes reachability and normal behavior before any probe is attempted",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				probe.request, probe.response, &probe.mutation,
				fmt.Sprintf("syntax=%s payload=%s expected=literal_reflection actual=evaluated_product=%d", variant.name, variant.payload, product),
				reason,
			)),
		},
	}
}
