package ssrfactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed SSRF -- evidence
// built exclusively via detection.MutationEvidence, never a second,
// SSRF-specific evidence shape. Only the fields a detector is
// expected to set are populated here -- DetectorID/Host/Port/URL/
// Method/AffectedEndpoint/IdentityContext/ScanID/Source/timestamps are
// filled by the engine's normalizeFinding (Phase 3.1/3.19), which
// never overwrites what's already set here.
func (d *Detector) finding(t detection.Target, baseline probeResult, modeA *probeResult, markerFound bool, modeB probeResult, token, callbackURL string, observations []ssrf.Observation) models.Finding {
	callbackConfirmed := len(observations) > 0

	severity, confidence := models.SeverityCritical, 0.0
	var proof string
	switch {
	case markerFound && callbackConfirmed:
		confidence = 0.95
		proof = "both response-based evidence (the internal resource's own distinctive marker was embedded in the application's response) AND out-of-band callback confirmation (the callback service recorded a server-side hit for the unique, per-probe callback URL injected through this parameter) were observed -- the strongest possible confirmation available to this detector"
	case callbackConfirmed:
		confidence = 0.9
		proof = "the callback service observed a server-side request for the unique, per-probe callback URL injected through this parameter -- direct, correlated confirmation of a server-side fetch, independent of anything the application itself returned"
	case markerFound:
		confidence = 0.85
		proof = "the application's own response embedded the internal resource's distinctive marker content -- direct evidence the application fetched that specific, scanner-owned resource server-side, not merely a reflected payload or a generic error"
	}

	obsDesc := "none"
	if callbackConfirmed {
		o := observations[0]
		obsDesc = fmt.Sprintf("%s %s from %s at %s", o.Method, o.Path, o.RemoteAddr, o.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"))
	}

	evidence := []models.Evidence{
		detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
			baseline.request, baseline.response, nil,
			fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
			"a plain, non-URL-shaped control value establishes reference response characteristics -- the endpoint is analyzable and the request completes, so the probes below can be judged as genuine SSRF evidence rather than baseline behavior",
		)),
	}
	if modeA != nil {
		evidence = append(evidence, detection.NewTypedRequestResponseEvidence(models.EvidenceKindProbe, "", "", detection.MutationEvidence(
			modeA.request, modeA.response, &modeA.mutation,
			fmt.Sprintf("mode=response-based marker_found=%v", markerFound),
			"the injected URL points at a scanner-owned internal resource server whose only content is a fixed, distinctive marker never present in the injected URL itself -- if the application's own response contains that marker, it fetched and embedded that resource's content server-side",
		)))
	}
	evidence = append(evidence, detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
		modeB.request, modeB.response, &modeB.mutation,
		fmt.Sprintf("mode=blind-oob callback_token=%s callback_observed=%v detail=%q", token, callbackConfirmed, obsDesc),
		proof,
	)))

	return models.Finding{
		VulnerabilityType: "ssrf",
		Title:             "Server-Side Request Forgery (SSRF)",
		Description: fmt.Sprintf(
			"The %q parameter on %s causes the application to perform a server-side request to an attacker-controlled destination, confirmed via %s. This may allow an attacker to reach internal services, cloud metadata endpoints, or other network resources not otherwise exposed.",
			t.Parameter, t.Path, modeDescription(markerFound, callbackConfirmed),
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Validate and restrict server-side-fetched URLs against an allowlist of expected hosts/schemes; never fetch a raw, attacker-supplied URL. Where outbound requests are required, route them through a proxy that blocks loopback, link-local, and private (RFC1918) address ranges, and disable following redirects to unvalidated destinations.",
		Evidence:          evidence,
	}
}

func modeDescription(markerFound, callbackConfirmed bool) string {
	switch {
	case markerFound && callbackConfirmed:
		return "both response-based (embedded resource marker) and out-of-band callback evidence"
	case callbackConfirmed:
		return "out-of-band callback evidence"
	default:
		return "response-based (embedded resource marker) evidence"
	}
}
