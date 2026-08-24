// Package traversalactive implements Phase 3.27's active path
// traversal detector -- built entirely on internal/mutation's
// canonical Request/Mutate/Execute model, reusing the pre-existing
// internal/detectors/traversal package's own TraversalCase type (an
// operator-configured, known relative traversal path plus its
// confirmation marker) and safe-proof strategy: a finding requires an
// EXACT, verbatim match of the configured marker in a probe's
// response -- never a status code, response length, timing, generic
// error, arbitrary response difference, or reflection. See
// docs/phase-3-27-path-traversal-active.md for the full architecture
// review.
//
// This is a SECOND, coexisting path traversal detector, deliberately
// not replacing internal/detectors/traversal (Phase 3.6, still
// registered but disabled -- it never imports internal/mutation and
// instead builds its own private *http.Request per probe, GET/
// query-location only, and additionally reports a weaker "suspicious"
// tier based on response differences this phase's own task explicitly
// prohibits relying on). This detector's stable ID
// ("path-traversal-active") is distinct so both can be independently
// enabled/disabled; internal/detectors/traversal is not modified by
// this phase.
package traversalactive

import (
	"bytes"
	"context"
	"fmt"
	nethttp "net/http"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/traversal"
	"sakanner/internal/mutation"
	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "path-traversal-active"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence -- matches every other active detector's own
// established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// path traversal detection. Needs at least one operator-configured
// traversal.TraversalCase -- mirroring traversal.New's own precedent
// exactly, including "a nil/empty cases slice makes every Detect call
// return OutcomeSkipped rather than panicking."
type Detector struct {
	cases []traversal.TraversalCase
}

// New returns a ready-to-register Detector.
func New(cases []traversal.TraversalCase) *Detector {
	return &Detector{cases: cases}
}

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Path Traversal Detector (Active)",
		Category:             "broken_access_control",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		Prerequisites: []string{
			"at least 1 operator-configured traversal.TraversalCase (a known relative traversal path plus its confirmation marker) supplied via New() -- see docs/phase-3-27-path-traversal-active.md section 1.1; without one, every Detect call returns OutcomeSkipped",
		},
		DefaultSeverity: models.SeverityCritical,
	}
}

// Eligible implements detection.Detector -- identical shape to
// internal/detectors/sqliactive/ssrfactive/cmdinjectionactive's own: a
// query-location parameter on a GET endpoint, or a form/JSON-body/
// path-location parameter on any method. Gated further by the
// file-path-like parameter-name heuristic.
func (Detector) Eligible(t detection.Target) bool {
	if t.Kind != detection.TargetKindEndpoint || t.Parameter == "" {
		return false
	}
	if !parameters.IsLikelyFilePathParameter(t.Parameter) {
		return false
	}
	switch t.ParameterLocation {
	case "query":
		return t.Method == nethttp.MethodGet
	case "body", "form", "path":
		return true
	default:
		return false
	}
}

// probeResult bundles one probe's mutation, request, and response.
type probeResult struct {
	mutation mutation.Mutation
	request  mutation.Request
	response mutation.Response
}

// Detect implements detection.Detector. All requests are built and
// issued exclusively via detection.NewMutationRequest/
// detection.NewTargetMutation/mutation.Mutate/Executor.ExecuteMutation
// -- the same canonical path every active detector since Phase 3.19
// uses; no detector-specific HTTP client, cookie jar, scope decision,
// or local filesystem call exists anywhere in this package.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if len(d.cases) == 0 {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if t.Parameter == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	loc := locationFor(t)
	original := detection.NewMutationRequest(t)

	baselineResp, err := x.ExecuteMutation(ctx, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("traversalactive: legitimate-access baseline probe: %w", err)
	}
	baselineResp.Body = truncate(baselineResp.Body)
	if !looksAllowed(baselineResp) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	baseline := probeResult{request: original, response: baselineResp}

	for _, c := range d.cases {
		for _, payload := range payloadsFor(loc, c.RelativePath) {
			m := detection.NewTargetMutation(t, loc, payload, encodingFor(loc))
			req, err := mutation.Mutate(original, m, mutation.Policy{})
			if err != nil {
				return detection.Result{}, fmt.Errorf("traversalactive: mutate (%s): %w", payload, err)
			}
			resp, err := x.ExecuteMutation(ctx, req)
			if err != nil {
				return detection.Result{}, fmt.Errorf("traversalactive: probe (%s): %w", payload, err)
			}
			resp.Body = truncate(resp.Body)

			if c.Marker != "" && bytes.Contains(resp.Body, []byte(c.Marker)) {
				probe := probeResult{mutation: m, request: req, response: resp}
				return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
					d.finding(t, c, baseline, probe),
				}}, nil
			}
		}
	}

	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

// payloadsFor returns the payload(s) this location should try for one
// TraversalCase's relative path -- query/form get the small, fixed set
// of pre-encoded wire representations (wireVariants); path/JSON get
// exactly one, the raw/unmodified representation (see variants.go's
// own doc comments for why).
func payloadsFor(loc mutation.Location, relPath string) []string {
	switch loc {
	case mutation.LocationQuery, mutation.LocationForm:
		return wireVariants(relPath)
	default: // LocationPath, LocationJSON
		return []string{rawPayload(relPath)}
	}
}

// encodingFor mirrors internal/detectors/cmdinjectionactive's own
// identical per-location split: query/form need EncodingVerbatim (the
// payload is already wire-encoded); path/JSON need EncodingEscaped
// (their own Mutate machinery applies exactly one correct escaping
// pass downstream).
func encodingFor(loc mutation.Location) mutation.Encoding {
	switch loc {
	case mutation.LocationQuery, mutation.LocationForm:
		return mutation.EncodingVerbatim
	default:
		return mutation.EncodingEscaped
	}
}

// locationFor maps t.ParameterLocation to the mutation.Location the
// probe's Mutation needs -- identical switch to every other "-active"
// detector's own.
func locationFor(t detection.Target) mutation.Location {
	switch t.ParameterLocation {
	case "form":
		return mutation.LocationForm
	case "body":
		return mutation.LocationJSON
	case "path":
		return mutation.LocationPath
	default:
		return mutation.LocationQuery
	}
}

// looksAllowed reports whether resp represents genuine access to
// something (2xx status with a non-empty body) -- mirrors
// internal/detectors/traversal's own identical, already-reviewed
// looksAllowed check, used ONLY to gate the baseline reachability
// probe, never as part of confirming a finding.
func looksAllowed(resp mutation.Response) bool {
	return resp.Outcome == mutation.OutcomeSuccess &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		len(bytes.TrimSpace(resp.Body)) > 0
}

func truncate(body []byte) []byte {
	if len(body) > maxBodySample {
		return body[:maxBodySample]
	}
	return body
}
