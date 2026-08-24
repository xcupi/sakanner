// Package xssactive implements Phase 3.19's active reflected-XSS
// detector -- the first detector built on internal/mutation's
// canonical Request/Mutate/Execute model and
// internal/detection.Executor.ExecuteMutation, proving the complete
// production path from discovery through finding for active,
// mutation-based detection. See docs/phase-3-19-active-detection.md.
//
// This is a SECOND, independent reflected-XSS detector, deliberately
// coexisting with internal/detectors/xssreflected (Phase 3.3) rather
// than replacing it -- xssreflected keeps its own private
// requestURL/probe pair, its own full test suite, and its own lab
// ground-truth mapping, all unmodified. This detector's stable ID
// ("xss-reflected-active") is distinct so both can be independently
// enabled/disabled.
//
// This package performs DETECTION only: reflected XSS via query and
// JSON-body parameters. It does not attempt stored XSS, DOM XSS, or
// blind XSS callbacks -- see this package's own test suite and
// docs/phase-3-19-active-detection.md section 14 for the full list of
// what is intentionally out of scope this phase.
package xssactive

import (
	"bytes"
	"context"
	"fmt"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "xss-reflected-active"

// reflectionMarker is a plain, alphanumeric probe value with no HTML/
// JS/JSON metacharacters -- confirms a parameter's value reaches the
// response AT ALL before any context-revealing (and more expensive)
// probe is sent. This independently re-derives the same two-phase
// idea internal/detectors/xssreflected (Phase 3.3) already
// established, not a copy of its code.
const reflectionMarker = "sakannerActiveXSSProbe"

// contextMarker is embedded inside the context-revealing payload so
// classifyReflection can locate exactly where injected content landed,
// distinct from any of the payload's own literal characters.
const contextMarker = "ACTIVEXSSMARK"

// contextPayload breaks out of a quoted HTML attribute value AND
// injects a fresh <script> element in one probe -- landing correctly
// in either a text or attribute context, and revealing whether the
// target already reflects inside an existing <script> block (see
// classifyReflection).
func contextPayload() string {
	return `"'><script>` + contextMarker + `</script>`
}

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's own
// established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// reflected XSS.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Reflected XSS Detector (Active)",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		DefaultSeverity:      models.SeverityCritical,
	}
}

// Eligible implements detection.Detector: a query-location parameter
// on a GET endpoint (matching xssreflected's own established scope),
// a JSON-body-location parameter on any method (a JSON body is never
// method-restricted the way a GET query string is), a (Phase 3.22)
// form-location parameter on any method -- mirroring "body"'s own
// permissiveness, identical in shape to internal/detectors/sqliactive's
// own Phase 3.21 adapter -- or (Phase 3.23) a path-location parameter
// on any method.
func (Detector) Eligible(t detection.Target) bool {
	if t.Kind != detection.TargetKindEndpoint || t.Parameter == "" {
		return false
	}
	switch t.ParameterLocation {
	case "query":
		return t.Method == "GET"
	case "body", "form", "path":
		return true
	default:
		return false
	}
}

// Detect implements detection.Detector. Two probes: a plain marker
// confirming reflection at all, then (for a non-JSON response) a
// context-revealing payload classified by classifyReflection. A JSON
// response is classified directly from the plain marker probe -- see
// docs/phase-3-19-active-detection.md section 8 for why an HTML-
// breakout payload is not meaningful evidence against a JSON API.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	// Phase 3.22/3.23: "form"/"path" are the minimum adapters those
	// phases add -- every other line in this file is unchanged.
	// Identical in shape to internal/detectors/sqliactive's own Phase
	// 3.21/3.23 adapters.
	var loc mutation.Location
	switch t.ParameterLocation {
	case "form":
		loc = mutation.LocationForm
	case "body":
		loc = mutation.LocationJSON
	case "path":
		loc = mutation.LocationPath
	default:
		loc = mutation.LocationQuery
	}
	original := detection.NewMutationRequest(t)

	m1 := detection.NewTargetMutation(t, loc, reflectionMarker, mutation.EncodingEscaped)
	req1, err := mutation.Mutate(original, m1, mutation.Policy{})
	if err != nil {
		return detection.Result{}, fmt.Errorf("xssactive: mutate reflection probe: %w", err)
	}
	resp1, err := x.ExecuteMutation(ctx, req1)
	if err != nil {
		return detection.Result{}, fmt.Errorf("xssactive: reflection probe: %w", err)
	}
	if resp1.Outcome != mutation.OutcomeSuccess || !bytes.Contains(bounded(resp1.Body), []byte(reflectionMarker)) {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	if isJSONContentType(resp1.ContentType) {
		return d.jsonResult(t, req1, m1, resp1), nil
	}

	payload := contextPayload()
	m2 := detection.NewTargetMutation(t, loc, payload, mutation.EncodingEscaped)
	req2, err := mutation.Mutate(original, m2, mutation.Policy{})
	if err != nil {
		return detection.Result{}, fmt.Errorf("xssactive: mutate context probe: %w", err)
	}
	resp2, err := x.ExecuteMutation(ctx, req2)
	if err != nil {
		return detection.Result{}, fmt.Errorf("xssactive: context probe: %w", err)
	}
	if resp2.Outcome != mutation.OutcomeSuccess {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	kind := classifyReflection(bounded(resp2.Body), payload)
	if kind == ReflectionNone || kind == ReflectionHTMLEncoded {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.htmlFinding(t, kind, req1, m1, resp1, req2, m2, resp2),
	}}, nil
}

func bounded(body []byte) []byte {
	if len(body) > maxBodySample {
		return body[:maxBodySample]
	}
	return body
}
