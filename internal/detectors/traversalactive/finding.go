package traversalactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/traversal"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed path traversal --
// evidence built exclusively via detection.MutationEvidence, never a
// second, traversal-specific evidence shape. Only the fields a
// detector is expected to set are populated here -- DetectorID/Host/
// Port/URL/Method/AffectedEndpoint/IdentityContext/ScanID/Source/
// timestamps are filled by the engine's normalizeFinding, which never
// overwrites what's already set here.
func (d *Detector) finding(t detection.Target, c traversal.TraversalCase, baseline, probe probeResult) models.Finding {
	reason := fmt.Sprintf(
		"the response contains %q -- the exact, operator-configured protected-resource marker -- which could only appear if the traversal-shaped value reached a file/resource lookup that escaped the endpoint's intended root, not merely reflection, a generic response, or an allowed status code",
		c.Marker,
	)

	return models.Finding{
		VulnerabilityType: "path_traversal",
		Title:             "Path Traversal (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows a traversal-shaped value (%s) to reach a resource lookup that escapes the endpoint's intended root, confirmed by the protected resource's own known marker content appearing in the response.",
			t.Parameter, t.Path, c.RelativePath,
		),
		Severity:          models.SeverityCritical,
		Confidence:        0.9,
		AffectedParameter: t.Parameter,
		Remediation:       "Canonicalize the resolved path and verify it is still contained within the intended allowed root before using it, server-side, on every request -- never rely on blocklisting \"..\" substrings alone. Prefer an allowlist/ID-based lookup where practical (never constructing a filesystem path from client input at all), but containment verification on the fully-resolved path is the actual fix.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
				"the endpoint's own originally-discovered value, unmutated, establishes reachability and normal behavior before any probe is attempted",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				probe.request, probe.response, &probe.mutation,
				fmt.Sprintf("relative_path=%s expected=denied actual=protected_resource_marker_matched proof=%s", c.RelativePath, c.Marker),
				reason,
			)),
		},
	}
}
