// Package cmdinjectionactive implements Phase 3.26's active OS command
// injection detector -- built entirely on internal/mutation's
// canonical Request/Mutate/Execute model, reusing the pre-existing
// internal/detectors/cmdinjection package's own already-reviewed
// safe-proof strategy (a freshly generated, unpredictable per-probe
// correlation token, injected as "<separator><fake-lab-command-name>
// <token>", confirmed ONLY on an exact match of the constant marker
// prefix immediately followed by that EXACT token). See
// docs/phase-3-26-command-injection-active.md for the full
// architecture review.
//
// This is a SECOND, coexisting command-injection detector,
// deliberately not replacing internal/detectors/cmdinjection (Phase
// 3.7, still registered and enabled -- it never imports
// internal/mutation and instead builds its own private *http.Request
// per probe, GET/query-location only). This detector's stable ID
// ("command-injection-active") is distinct so both can be
// independently enabled/disabled; internal/detectors/cmdinjection is
// not modified by this phase.
//
// CRITICAL SAFETY PROPERTY: this package never constructs a local
// shell command, never imports "os/exec", and never interprets target
// input, a target URL, or a target response as anything other than
// HTTP request/response data -- see shell_isolation_test.go.
package cmdinjectionactive

import (
	"bytes"
	"context"
	"fmt"
	nethttp "net/http"

	"github.com/google/uuid"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "command-injection-active"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence/comparison -- matches every other active
// detector's own established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// OS command injection detection. Needs no constructor-injected
// dependency -- mirroring internal/detectors/cmdinjection.New()'s own
// reasoning exactly (its correlation mechanism is entirely
// self-contained), so it registers enabled by default, not behind a
// nil-dependency gate.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Command Injection Detector (Active)",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		DefaultSeverity:      models.SeverityCritical,
	}
}

// Eligible implements detection.Detector -- identical shape to
// internal/detectors/sqliactive/ssrfactive's own: a query-location
// parameter on a GET endpoint, or a form/JSON-body/path-location
// parameter on any method (see
// docs/phase-3-26-command-injection-active.md section 1.3 for why,
// unlike idoractive, there is no reason to restrict to GET-only here).
// Gated further by the command-like parameter-name heuristic.
func (Detector) Eligible(t detection.Target) bool {
	if t.Kind != detection.TargetKindEndpoint || t.Parameter == "" {
		return false
	}
	if !parameters.IsLikelyCommandParameter(t.Parameter) {
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
// or local shell invocation exists anywhere in this package.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if t.Parameter == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	loc := locationFor(t)
	original := detection.NewMutationRequest(t)

	baseline, err := d.executeAndBound(ctx, x, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("cmdinjectionactive: baseline probe: %w", err)
	}
	if !looksAllowed(baseline) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	for _, variant := range commandVariants() {
		token := uuid.NewString()
		payload, encoding := payloadFor(loc, variant, token)

		m := detection.NewTargetMutation(t, loc, payload, encoding)
		req, err := mutation.Mutate(original, m, mutation.Policy{})
		if err != nil {
			return detection.Result{}, fmt.Errorf("cmdinjectionactive: mutate (%s): %w", variant.name, err)
		}
		resp, err := d.executeAndBound(ctx, x, req)
		if err != nil {
			return detection.Result{}, fmt.Errorf("cmdinjectionactive: probe (%s): %w", variant.name, err)
		}

		expected := markerPrefix + token
		if bytes.Contains(resp.Body, []byte(expected)) {
			probe := probeResult{mutation: m, request: req, response: resp}
			baselineProbe := probeResult{request: original, response: baseline}
			return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
				d.finding(t, baselineProbe, probe, variant, token),
			}}, nil
		}
	}

	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

// executeAndBound issues req and truncates its response body to
// maxBodySample -- the ONE place this package ever issues a request.
func (d *Detector) executeAndBound(ctx context.Context, x *detection.Executor, req mutation.Request) (mutation.Response, error) {
	resp, err := x.ExecuteMutation(ctx, req)
	if err != nil {
		return mutation.Response{}, err
	}
	if len(resp.Body) > maxBodySample {
		resp.Body = resp.Body[:maxBodySample]
	}
	return resp, nil
}

// payloadFor builds this variant's wire payload and the Encoding it
// must be sent with -- query/form need the pre-encoded,
// EncodingVerbatim form (mirroring internal/detectors/cmdinjection's
// own established technique); path/JSON need the raw, literal,
// EncodingEscaped form (their own Mutate machinery applies exactly one
// correct escaping pass downstream -- see variants.go's own doc
// comments for why pre-encoding those two would double-encode).
func payloadFor(loc mutation.Location, variant commandVariant, token string) (string, mutation.Encoding) {
	switch loc {
	case mutation.LocationQuery, mutation.LocationForm:
		return wireEncodedPayload(variant.separator, token), mutation.EncodingVerbatim
	default: // LocationPath, LocationJSON
		return rawPayload(variant.separator, token), mutation.EncodingEscaped
	}
}

// locationFor maps t.ParameterLocation to the mutation.Location the
// probe's Mutation needs -- identical switch to
// internal/detectors/sqliactive/xssactive/ssrfactive's own.
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
// internal/detectors/cmdinjection's own identical, already-reviewed
// looksAllowed check, used ONLY to gate the baseline reachability
// probe, never as part of confirming a finding (see
// docs/phase-3-26-command-injection-active.md section 2: THIS check
// never contributes to a finding's own evidence standard, only to
// deciding whether the endpoint is reachable enough to probe at all).
func looksAllowed(resp mutation.Response) bool {
	return resp.Outcome == mutation.OutcomeSuccess &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		len(bytes.TrimSpace(resp.Body)) > 0
}
