// Package sstiactive implements Phase 3.29's active Server-Side
// Template Injection (SSTI) detector -- built entirely on
// internal/mutation's canonical Request/Mutate/Execute model. There is
// no pre-existing "internal/detectors/ssti" package to coexist with
// (see docs/phase-3-29-active-detection-coverage-review.md): this is
// the first detector for this vulnerability class, named with the
// "-active" suffix for consistency with the rest of the detector
// family, mirroring openredirectactive's own identical precedent
// (Phase 3.28, also no legacy sibling).
//
// A finding requires the response to contain the EXACT numeric
// product of two operands freshly, randomly chosen for this one probe
// -- never a status code, timing, generic error, or the raw payload
// text reflected unevaluated. See
// docs/phase-3-29-active-detection-coverage-review.md's selection
// rationale for why this proof strategy was chosen.
package sstiactive

import (
	"context"
	"fmt"
	"strconv"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "ssti-active"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence -- matches every other active detector's own
// established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// SSTI detection. Needs no operator-configured dependency at all --
// New() takes no arguments -- since its correlation mechanism (a
// freshly generated, unpredictable per-probe arithmetic product) is
// entirely self-contained, mirroring cmdinjectionactive's own
// identical "no external config needed" precedent, not
// ssrfactive/traversalactive/openredirectactive's disabled-by-default
// one.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Server-Side Template Injection Detector (Active)",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		DefaultSeverity:      models.SeverityHigh,
	}
}

// Eligible mirrors sqliactive/xssactive's own shape -- no
// parameter-name heuristic gate, since SSTI is meaningful against
// essentially any parameter whose value might be rendered through a
// template (unlike SSRF/command-injection/traversal/redirect, which
// are only meaningful against a parameter whose NAME suggests the
// right kind of value): a query-location parameter on a GET endpoint,
// or a form/JSON-body/path-location parameter on any method.
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

// probeResult bundles one probe's mutation, request, and response.
type probeResult struct {
	mutation mutation.Mutation
	request  mutation.Request
	response mutation.Response
}

// Detect implements detection.Detector. All requests are built and
// issued exclusively via detection.NewMutationRequest/
// detection.NewTargetMutation/mutation.Mutate/Executor.ExecuteMutation
// -- no detector-specific HTTP client, template engine, or code
// execution exists anywhere in this package; the only computation
// performed is a single Go-native integer multiplication.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if t.Parameter == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	loc := locationFor(t)
	original := detection.NewMutationRequest(t)

	baselineResp, err := x.ExecuteMutation(ctx, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sstiactive: baseline probe: %w", err)
	}
	baselineResp.Body = truncate(baselineResp.Body)
	if !looksReachable(baselineResp) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	baseline := probeResult{request: original, response: baselineResp}

	a, b := randomOperands()
	product := a * b
	productStr := strconv.Itoa(product)
	if containsIsolatedNumber(baselineResp.Body, productStr) {
		// Defensive only: astronomically unlikely (a fresh random
		// product coincidentally already present in the baseline's
		// own, unmutated content) -- if it ever happens, this probe
		// cannot distinguish causation, so skip rather than risk a
		// false positive.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	for _, variant := range templateVariants(a, b) {
		m := detection.NewTargetMutation(t, loc, variant.payload, mutation.EncodingEscaped)
		req, err := mutation.Mutate(original, m, mutation.Policy{})
		if err != nil {
			return detection.Result{}, fmt.Errorf("sstiactive: mutate (%s): %w", variant.name, err)
		}
		resp, err := x.ExecuteMutation(ctx, req)
		if err != nil {
			return detection.Result{}, fmt.Errorf("sstiactive: probe (%s): %w", variant.name, err)
		}
		resp.Body = truncate(resp.Body)

		if containsIsolatedNumber(resp.Body, productStr) {
			probe := probeResult{mutation: m, request: req, response: resp}
			return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
				d.finding(t, variant, a, b, product, baseline, probe),
			}}, nil
		}
	}

	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

// locationFor maps t.ParameterLocation to the mutation.Location the
// probe's Mutation needs -- identical switch to every other
// "-active" detector's own.
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

// looksReachable reports whether resp represents a genuine, non-empty
// HTTP response worth proceeding from -- used ONLY to gate the
// baseline reachability probe.
func looksReachable(resp mutation.Response) bool {
	return resp.Outcome == mutation.OutcomeSuccess &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		len(resp.Body) > 0
}

func truncate(body []byte) []byte {
	if len(body) > maxBodySample {
		return body[:maxBodySample]
	}
	return body
}
