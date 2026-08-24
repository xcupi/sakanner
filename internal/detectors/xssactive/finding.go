package xssactive

import (
	"fmt"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// confidenceTier names a (severity, confidence, reason) triple for one
// ReflectionKind -- the ONLY place this mapping is defined, mirroring
// internal/detectors/sqli's own established convention of a single,
// explicit classify function rather than inline severity logic
// scattered through Detect.
type confidenceTier struct {
	severity   models.Severity
	confidence float64
	reason     string
}

func classify(kind ReflectionKind) confidenceTier {
	switch kind {
	case ReflectionJavaScript:
		return confidenceTier{models.SeverityCritical, 0.95, "the probe payload was reflected raw, unescaped, inside an already-open <script> block -- the single most directly executable reflection context"}
	case ReflectionAttribute:
		return confidenceTier{models.SeverityCritical, 0.9, "the probe payload was reflected raw, unescaped, inside an HTML attribute value, breaking out of it"}
	case ReflectionExact:
		return confidenceTier{models.SeverityCritical, 0.9, "the probe payload was reflected raw, unescaped, in ordinary HTML text"}
	case ReflectionJSONString:
		return confidenceTier{models.SeverityMedium, 0.5, "the probe marker was reflected inside a JSON response body -- whether this is exploitable depends entirely on how the JSON is consumed downstream, which this detector cannot observe, so this is reported at lower confidence than a direct HTML/JavaScript reflection"}
	default:
		return confidenceTier{}
	}
}

// htmlFinding builds a models.Finding for an HTML/JS-context
// confirmed reflection. req1/resp1 (the plain-marker baseline) and
// req2/m2/resp2 (the context probe that actually confirmed the
// finding) are both captured as separate evidence items, mirroring
// internal/detectors/sqli's own baseline+probe evidence convention.
func (d Detector) htmlFinding(t detection.Target, kind ReflectionKind, req1 mutation.Request, m1 mutation.Mutation, resp1 mutation.Response, req2 mutation.Request, m2 mutation.Mutation, resp2 mutation.Response) models.Finding {
	tier := classify(kind)
	cmp := mutation.Compare(resp1, resp2)

	return models.Finding{
		VulnerabilityType: "reflected_xss",
		Title:             "Reflected Cross-Site Scripting (Active)",
		Description: fmt.Sprintf(
			"The %q parameter on %s reflects attacker-controlled input into the response in a %s context without adequate sanitization, based on active mutation-based probing. This may allow an attacker to execute arbitrary JavaScript in a victim's browser.",
			t.Parameter, t.Path, kind,
		),
		Severity:          tier.severity,
		Confidence:        tier.confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Context-appropriately encode all user-controlled output before rendering it into HTML (HTML-entity-encode text content, attribute-encode attribute values, avoid rendering user input into <script> blocks at all). Prefer a templating engine with automatic contextual escaping over manual string concatenation.",
		Evidence: []models.Evidence{
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.MutationEvidence(
				req1, resp1, &m1,
				fmt.Sprintf("baseline_status=%d marker_reflected=true", resp1.StatusCode),
				"a plain, alphanumeric marker with no HTML/JS metacharacters establishes that this parameter's value reaches the response at all, before any context-revealing probe is judged",
			)),
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				req2, resp2, &m2,
				fmt.Sprintf("reflection_context=%s status=%d structurally_different_from_baseline=%v", kind, resp2.StatusCode, cmp.StructurallyDifferent),
				tier.reason,
			)),
		},
	}
}

// jsonResult builds the detection.Result for a JSON-response
// reflection, classified directly from the plain-marker baseline probe
// (resp1) -- see Detect's own doc comment for why no HTML-breakout
// context probe is meaningful against a JSON API.
func (d Detector) jsonResult(t detection.Target, req1 mutation.Request, m1 mutation.Mutation, resp1 mutation.Response) detection.Result {
	tier := classify(ReflectionJSONString)
	f := models.Finding{
		VulnerabilityType: "reflected_xss",
		Title:             "Reflected Cross-Site Scripting (Active, JSON Response)",
		Description: fmt.Sprintf(
			"The %q parameter on %s is reflected verbatim inside a JSON API response, based on active mutation-based probing. This does not by itself confirm HTML/JavaScript execution -- whether it is exploitable depends on how the consuming application renders this JSON field.",
			t.Parameter, t.Path,
		),
		Severity:          tier.severity,
		Confidence:        tier.confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "If this JSON field is ever rendered into HTML by a consumer, ensure that consumer context-appropriately encodes it before rendering. Do not assume a JSON API response is inherently safe to render as HTML without escaping.",
		Evidence: []models.Evidence{
			detection.NewRequestResponseEvidence("", "", detection.MutationEvidence(
				req1, resp1, &m1,
				fmt.Sprintf("json_response=true status=%d marker_reflected=true", resp1.StatusCode),
				tier.reason,
			)),
		},
	}
	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{f}}
}
