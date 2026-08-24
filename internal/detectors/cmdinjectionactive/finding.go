package cmdinjectionactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// finding builds a models.Finding for a confirmed command injection --
// evidence built exclusively via detection.MutationEvidence, never a
// second, command-injection-specific evidence shape. Only the fields a
// detector is expected to set are populated here -- DetectorID/Host/
// Port/URL/Method/AffectedEndpoint/IdentityContext/ScanID/Source/
// timestamps are filled by the engine's normalizeFinding, which never
// overwrites what's already set here.
func (d *Detector) finding(t detection.Target, baseline, probe probeResult, variant commandVariant, token string) models.Finding {
	expected := markerPrefix + token
	reason := fmt.Sprintf(
		"the response contains %q -- the exact constant marker prefix immediately followed by THIS probe's own freshly generated, unpredictable token -- which could only appear if the injected value was interpreted as a command, not merely reflected, stored, or matched against unrelated static content",
		expected,
	)

	return models.Finding{
		VulnerabilityType: "command_injection",
		Title:             "OS Command Injection (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows a shell-metacharacter-prefixed value to reach command execution. A freshly generated, unpredictable correlation token injected via the %s separator was echoed back through confirmed execution, not reflection.",
			t.Parameter, t.Path, variant.name,
		),
		Severity:          models.SeverityCritical,
		Confidence:        0.95,
		AffectedParameter: t.Parameter,
		Remediation:       "Never pass user-controlled input to a shell or command interpreter. Use language-level APIs that execute a fixed program with an argument LIST (never a concatenated/interpolated command string), or an allowlist of permitted values, so shell metacharacters can never change what gets executed.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				baseline.request, baseline.response, nil,
				fmt.Sprintf("baseline_status=%d", baseline.response.StatusCode),
				"the endpoint's own originally-discovered value, unmutated, establishes reachability and normal behavior before any probe is attempted",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				probe.request, probe.response, &probe.mutation,
				fmt.Sprintf("separator=%s expected=input_treated_as_data actual=controlled_command_execution_occurred proof=%s", variant.name, expected),
				reason,
			)),
		},
	}
}
