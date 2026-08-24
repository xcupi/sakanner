// Package openredirectactive implements Phase 3.28's active open
// redirect detector -- built entirely on internal/mutation's canonical
// Request/Mutate/Execute model. There is no pre-existing
// "internal/detectors/openredirect" package to coexist with (see
// docs/phase-3-28-open-redirect-active.md section 1.1) -- this is the
// first active OR passive detector for this vulnerability class.
//
// A finding requires the response to be a genuine 3xx redirect whose
// Location header, once PARSED and RESOLVED (RFC 3986 relative-
// reference resolution, exactly matching net/http's own redirect-
// following) against the request's own URL, produces a destination
// whose host/port/path exactly match an operator-configured,
// out-of-scope destination URL -- never a status code, reflection,
// body content, or substring match on the raw Location text. See
// docs/phase-3-28-open-redirect-active.md section 2.
package openredirectactive

import (
	"context"
	"fmt"
	"net/url"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "open-redirect-active"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence -- matches every other active detector's own
// established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// open-redirect detection. Needs an operator-configured, known,
// out-of-scope destination URL -- a nil/empty destination makes every
// Detect call return OutcomeSkipped rather than panicking, mirroring
// traversalactive/ssrfactive's own identical "no config, no probing"
// precedent.
type Detector struct {
	destination    string
	destinationURL *url.URL
}

// New returns a ready-to-register Detector. destinationURL must be an
// absolute URL with an explicit path (e.g.
// "http://external.scanner.test/sakanner-lab-redirect-marker") --
// operator-configured, never guessed. An invalid or empty
// destinationURL makes every Detect call return OutcomeSkipped.
func New(destinationURL string) *Detector {
	d := &Detector{destination: destinationURL}
	if destinationURL != "" {
		if u, err := url.Parse(destinationURL); err == nil && u.Host != "" {
			d.destinationURL = u
		}
	}
	return d
}

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Open Redirect Detector (Active)",
		Category:             "broken_access_control",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		Prerequisites: []string{
			"an operator-configured, known, out-of-scope destination URL supplied via New() -- see docs/phase-3-28-open-redirect-active.md section 3; without one, every Detect call returns OutcomeSkipped",
		},
		DefaultSeverity: models.SeverityMedium,
	}
}

// Eligible mirrors sqliactive/ssrfactive/cmdinjectionactive/
// traversalactive's own identical shape: a query-location parameter
// on a GET endpoint, or a form/JSON-body/path-location parameter on
// any method, gated by the shared URL-parameter name heuristic.
func (Detector) Eligible(t detection.Target) bool {
	if t.Kind != detection.TargetKindEndpoint || t.Parameter == "" {
		return false
	}
	if !parameters.IsLikelyURLParameter(t.Parameter) {
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
	resolved *url.URL
	raw      string
}

// Detect implements detection.Detector. All requests are built and
// issued exclusively via detection.NewMutationRequest/
// detection.NewTargetMutation/mutation.Mutate/Executor.ExecuteMutation
// -- no detector-specific HTTP client, redirect-following, or scope
// decision exists anywhere in this package. Following (or refusing to
// follow) any redirect hop remains entirely the shared Executor's own
// scope-safe responsibility (docs/phase-3-28-open-redirect-active.md
// section 1.3) -- this detector only ever INSPECTS the response it is
// handed.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if d.destinationURL == nil {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if t.Parameter == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	loc := locationFor(t)
	original := detection.NewMutationRequest(t)

	baselineResp, err := x.ExecuteMutation(ctx, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("openredirectactive: baseline probe: %w", err)
	}
	baselineResp.Body = truncate(baselineResp.Body)
	if !looksReachable(baselineResp) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	baseline := probeResult{request: original, response: baselineResp}

	for _, payload := range payloadsFor(loc, d.destination) {
		m := detection.NewTargetMutation(t, loc, payload.value, encodingFor(loc, payload.verbatim))
		req, err := mutation.Mutate(original, m, mutation.Policy{})
		if err != nil {
			return detection.Result{}, fmt.Errorf("openredirectactive: mutate (%s): %w", payload.name, err)
		}
		resp, err := x.ExecuteMutation(ctx, req)
		if err != nil {
			return detection.Result{}, fmt.Errorf("openredirectactive: probe (%s): %w", payload.name, err)
		}
		resp.Body = truncate(resp.Body)

		if resp.Outcome != mutation.OutcomeSuccess || !isRedirectStatus(resp.StatusCode) {
			continue
		}
		resolved, raw, ok := resolveLocation(req.URL(), resp)
		if !ok {
			continue
		}
		if matchesDestination(resolved, d.destinationURL) {
			probe := probeResult{mutation: m, request: req, response: resp, resolved: resolved, raw: raw}
			return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
				d.finding(t, baseline, probe),
			}}, nil
		}
	}

	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

// payloadsFor returns the payload(s) this location should try --
// query/form get the small, fixed wireVariants set; path/JSON get
// exactly one, the raw/unmodified representation.
func payloadsFor(loc mutation.Location, destination string) []redirectVariant {
	switch loc {
	case mutation.LocationQuery, mutation.LocationForm:
		return wireVariants(destination)
	default: // LocationPath, LocationJSON
		return []redirectVariant{{name: "raw", value: rawPayload(destination)}}
	}
}

// encodingFor mirrors traversalactive/cmdinjectionactive's own
// identical per-location split: query/form need EncodingVerbatim only
// for a payload this package has already percent-encoded itself
// (verbatim==true); every other case uses EncodingEscaped, letting
// the destination location's own downstream escaping pass apply
// exactly once.
func encodingFor(loc mutation.Location, verbatim bool) mutation.Encoding {
	if verbatim && (loc == mutation.LocationQuery || loc == mutation.LocationForm) {
		return mutation.EncodingVerbatim
	}
	return mutation.EncodingEscaped
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

// looksReachable reports whether resp represents a genuine HTTP
// response worth proceeding from -- used ONLY to gate the baseline
// reachability probe. Unlike traversalactive's looksAllowed, this
// does NOT require a 2xx status: a redirect-triggering endpoint's own
// baseline response is very often ITSELF a legitimate 3xx (e.g. the
// originally-discovered/crawled value redirecting somewhere safe),
// which must not be treated as "unreachable".
func looksReachable(resp mutation.Response) bool {
	return resp.Outcome == mutation.OutcomeSuccess && resp.StatusCode > 0
}

func truncate(body []byte) []byte {
	if len(body) > maxBodySample {
		return body[:maxBodySample]
	}
	return body
}
