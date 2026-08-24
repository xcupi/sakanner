package openredirectactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed open redirect --
// evidence built exclusively via detection.MutationEvidence, never a
// second, detector-specific evidence shape. Only the fields a
// detector is expected to set are populated here -- DetectorID/Host/
// Port/URL/Method/AffectedEndpoint/IdentityContext/ScanID/Source/
// timestamps are filled by the engine's normalizeFinding, which never
// overwrites what's already set here.
func (d *Detector) finding(t detection.Target, baseline, probe probeResult) models.Finding {
	reason := fmt.Sprintf(
		"the response is a redirect (status %d) whose Location header (%q), once parsed and resolved against the request's own URL, points to %q -- an exact host/port/path match with the operator-configured, out-of-scope destination -- not merely a reflection, a status code, or the payload appearing as a substring of the Location text",
		probe.response.StatusCode, probe.raw, probe.resolved.String(),
	)

	return models.Finding{
		VulnerabilityType: "open_redirect",
		Title:             "Open Redirect (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s causes the server to issue a redirect (status %d) to an out-of-scope, attacker-controlled destination (%s), confirmed by resolving the response's own Location header rather than any status code, reflection, or substring signal.",
			t.Parameter, t.Path, probe.response.StatusCode, probe.resolved.String(),
		),
		Severity:          models.SeverityMedium,
		Confidence:        0.9,
		AffectedParameter: t.Parameter,
		Remediation:       "Never redirect to a raw, client-supplied destination. Validate the destination against a fixed allowlist of paths/hosts, or restrict redirects to relative, same-origin paths only -- verified AFTER resolving the value, never by a prefix/substring check on the raw input alone.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
				"the endpoint's own originally-discovered value, unmutated, establishes reachability before any probe is attempted",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				probe.request, probe.response, &probe.mutation,
				fmt.Sprintf("location_raw=%s resolved_destination=%s expected=denied actual=redirect_to_configured_destination", probe.raw, probe.resolved.String()),
				reason,
			)),
		},
	}
}
