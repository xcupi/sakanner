package idoractive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// probeResult bundles one probe's request/response -- mirrors
// internal/detectors/sqliactive's own probeResult exactly, minus the
// mutation field for the two probes (baseline, cross-test) that never
// mutate anything.
type probeResult struct {
	request  mutation.Request
	response mutation.Response
}

// finding builds a models.Finding for a confirmed horizontal
// authorization failure -- the three-probe evidence chain described in
// docs/phase-3-24-authorization.md section 3. Only the fields a
// detector is expected to set are populated here; DetectorID/Host/
// Port/URL/Method/AffectedEndpoint/ScanID/Source/timestamps are filled
// by the engine's normalizeFinding, which never overwrites what's
// already set here. IdentityContext IS set explicitly, to the COMPARE
// identity (the acting identity that obtained the unauthorized
// access) -- normalizeFinding only fills it in when still empty, so
// this deliberately overrides the default (which would otherwise be
// the BASELINE identity, copied from t.IdentityContext -- see
// docs/phase-3-24-authorization.md section 12).
func (d *Detector) finding(t detection.Target, objectValue string, baseline, crossTest, knownBad probeResult, knownBadMutation mutation.Mutation, echoed bool) models.Finding {
	severity, confidence := models.SeverityCritical, 0.75
	corroboration := "the cross-test response did not echo the object identifier verbatim, so this finding relies on structural similarity to the baseline alone"
	if echoed {
		confidence = 0.9
		corroboration = "the cross-test response also echoed the object identifier itself, corroborating that the SAME specific object was returned, not merely a structurally similar page"
	}

	baselineIdentity := t.IdentityContext
	reason := fmt.Sprintf(
		"identity %q, using its own independent session, requested the SAME object (%q=%q) that identity %q's session originally discovered and could access. The response identity %q received was structurally similar to identity %q's own baseline response for that object, and structurally DIFFERENT from a known-bad control request (the same parameter, a synthetic value no identity owns) issued through identity %q's own session -- ruling out a generically identical response for every value. %s.",
		d.compareIdentity, t.Parameter, objectValue, baselineIdentity, d.compareIdentity, baselineIdentity, d.compareIdentity, corroboration,
	)

	return models.Finding{
		VulnerabilityType: "idor",
		Title:             "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows identity %q to access an object that was discovered and originally accessed under a different identity (%q), without authorization. %s",
			t.Parameter, t.Path, d.compareIdentity, baselineIdentity, reason,
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		IdentityContext:   d.compareIdentity,
		Remediation:       "Verify object ownership (authenticated_identity == object.owner) on every request that accesses a specific object, server-side, before returning it -- never rely on the client only requesting identifiers it is supposed to have. Prefer non-guessable, per-identity-scoped references where practical, but ownership verification is the actual fix, not obscurity.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("who=%s what=%s=%s role=baseline status=%d", baselineIdentity, t.Parameter, objectValue, baseline.response.StatusCode),
				"the discovering identity's own successful access establishes the reference response the cross-test below is compared against",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				crossTest.request, crossTest.response, nil,
				fmt.Sprintf("who=%s what=%s=%s role=cross-test status=%d echoed_object_value=%v", d.compareIdentity, t.Parameter, objectValue, crossTest.response.StatusCode, echoed),
				reason,
			)),
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindProbe, "", "", detection.MutationEvidence(
				knownBad.request, knownBad.response, &knownBadMutation,
				fmt.Sprintf("who=%s what=%s=%s role=known-bad-control status=%d", d.compareIdentity, t.Parameter, knownBadMutation.Value, knownBad.response.StatusCode),
				"a synthetic, guaranteed-nonexistent value issued through the same compare identity's own session establishes what a denied/nonexistent-object response looks like from that identity's own perspective, so the cross-test response above can be judged against it rather than in isolation",
			)),
		},
	}
}
