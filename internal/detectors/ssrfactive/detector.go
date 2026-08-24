// Package ssrfactive implements Phase 3.25's active SSRF (Server-Side
// Request Forgery) detector -- built entirely on internal/mutation's
// canonical Request/Mutate/Execute model, reusing the existing
// internal/detectors/ssrf.CallbackClient interface (and, in the lab,
// lab.SSRFCallbackServer) for out-of-band correlation. See
// docs/phase-3-25-ssrf-active-detection.md for the full architecture
// review.
//
// This is a SECOND, coexisting SSRF detector, deliberately not
// replacing internal/detectors/ssrf (Phase 3.4, still registered but
// disabled -- it never imports internal/mutation and instead builds
// its own private *http.Request per probe, and its own weaker
// response-diff/error-phrase fallback tiers fall below this phase's
// own stricter evidence bar). This detector's stable ID
// ("ssrf-active") is distinct so both can be independently enabled/
// disabled; internal/detectors/ssrf is not modified by this phase.
//
// Detection only. Two evidence modes, NEITHER ever based on status
// code, response-length/timing difference, a reflected URL, a generic
// error, or successful DNS resolution alone (see this package's own
// response.go and docs/phase-3-25-ssrf-active-detection.md section 2):
//
//   - Mode A (response-based): the injected URL points at a
//     scanner-owned "internal resource" endpoint that serves a fixed,
//     distinctive marker; a finding requires that marker to appear in
//     the TARGET APPLICATION's own response.
//   - Mode B (blind/OOB): the injected URL is a fresh, per-probe
//     callback URL (via CallbackClient); a finding requires the
//     callback service to have recorded an actual hit.
package ssrfactive

import (
	"context"
	"fmt"
	nethttp "net/http"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
	"sakanner/internal/mutation"
	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "ssrf-active"

// baselineValue mirrors internal/detectors/ssrf's own established
// choice exactly: a plain, non-URL-shaped control value, so even a
// genuinely vulnerable application's own input validation harmlessly
// rejects it without ever attempting a dial -- the baseline's only
// job is confirming the endpoint is analyzable, never testing fetch
// behavior itself.
const baselineValue = "sakannerSSRFActiveBASELINE"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence -- matches every other active detector's own
// established bound.
const maxBodySample = 256 * 1024

// Callback polling -- values copied verbatim from
// internal/detectors/ssrf/detector.go (already reviewed there, Phase
// 3.4); see docs/phase-3-25-ssrf-active-detection.md section 14 for
// why these bounds are small, fully deterministic, and ctx-aware.
const (
	callbackPollInterval = 10 * time.Millisecond
	callbackMaxWait      = 200 * time.Millisecond
)

// Detector implements detection.Detector for active, mutation-based
// SSRF detection.
type Detector struct {
	callback               ssrf.CallbackClient
	internalResourceURL    string
	internalResourceMarker string
}

// New returns a ready-to-register Detector. cb is required for
// meaningful detection -- a nil cb makes every Detect call return
// OutcomeSkipped, mirroring internal/detectors/ssrf.New's own
// precedent exactly. internalResourceURL/internalResourceMarker, if
// both non-empty, enable Mode A (response-based evidence) alongside
// Mode B (always attempted when cb is non-nil): internalResourceURL is
// injected as the payload; internalResourceMarker is the exact,
// distinctive substring that resource's own response is expected to
// contain, so a finding only fires when the TARGET APPLICATION's
// response embeds it. Either being empty gracefully skips Mode A
// only, never fatal (see
// docs/phase-3-25-ssrf-active-detection.md section 3). The marker is
// caller-supplied rather than a package constant so this package never
// needs to know what any specific internal-resource fixture's content
// looks like -- in the lab, this reuses the EXISTING
// ssrf-internal.scanner.test fixture's own already-distinctive
// response text, no new lab server required.
func New(cb ssrf.CallbackClient, internalResourceURL, internalResourceMarker string) *Detector {
	return &Detector{callback: cb, internalResourceURL: internalResourceURL, internalResourceMarker: internalResourceMarker}
}

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "SSRF Detector (Active)",
		Category:             "ssrf",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		Prerequisites: []string{
			"out-of-band callback infrastructure (ssrf.CallbackClient) supplied via New() -- see docs/phase-3-25-ssrf-active-detection.md section 11; without one, every Detect call returns OutcomeSkipped",
			"optional: a scanner-owned internal-resource URL for response-based (Mode A) evidence -- Mode B (callback correlation) alone is sufficient to enable this detector",
		},
		DefaultSeverity: models.SeverityCritical,
	}
}

// Eligible implements detection.Detector -- identical shape to
// internal/detectors/sqliactive/xssactive's own: a query-location
// parameter on a GET endpoint, or a form/JSON-body/path-location
// parameter on any method (see
// docs/phase-3-25-ssrf-active-detection.md section 1.3 for why, unlike
// idoractive, there is no reason to restrict to GET-only here -- SSRF
// probing never compares two identities' sessions against each
// other). Gated further by the URL-shaped parameter-name heuristic.
func (Detector) Eligible(t detection.Target) bool {
	if t.Kind != detection.TargetKindEndpoint || t.Parameter == "" {
		return false
	}
	if !parameters.IsLikelyURLParameter(t.Parameter) {
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
// uses; no detector-specific HTTP client, cookie jar, or scope
// decision exists anywhere in this package.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if d.callback == nil {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	loc := locationFor(t)
	original := detection.NewMutationRequest(t)

	baseline, err := d.probe(ctx, x, original, loc, t, baselineValue)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrfactive: baseline probe: %w", err)
	}
	if baseline.response.Outcome != mutation.OutcomeSuccess {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	var modeA *probeResult
	markerFound := false
	if d.internalResourceURL != "" && d.internalResourceMarker != "" {
		p, err := d.probe(ctx, x, original, loc, t, d.internalResourceURL)
		if err != nil {
			return detection.Result{}, fmt.Errorf("ssrfactive: mode-A probe: %w", err)
		}
		modeA = &p
		markerFound = responseContainsMarker(p.response, d.internalResourceMarker)
	}

	token, callbackURL, err := d.callback.NewToken(ctx)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrfactive: obtaining callback token: %w", err)
	}
	modeB, err := d.probe(ctx, x, original, loc, t, callbackURL)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrfactive: mode-B probe: %w", err)
	}
	observations, err := d.waitForCallback(ctx, token)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrfactive: waiting for callback: %w", err)
	}

	if !markerFound && len(observations) == 0 {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, baseline, modeA, markerFound, modeB, token, callbackURL, observations),
	}}, nil
}

// probe mutates original's target parameter to payload and executes
// it -- the ONLY way this package ever issues a request.
func (d *Detector) probe(ctx context.Context, x *detection.Executor, original mutation.Request, loc mutation.Location, t detection.Target, payload string) (probeResult, error) {
	m := detection.NewTargetMutation(t, loc, payload, mutation.EncodingEscaped)
	req, err := mutation.Mutate(original, m, mutation.Policy{})
	if err != nil {
		return probeResult{}, fmt.Errorf("mutate: %w", err)
	}
	resp, err := x.ExecuteMutation(ctx, req)
	if err != nil {
		return probeResult{}, err
	}
	if len(resp.Body) > maxBodySample {
		resp.Body = resp.Body[:maxBodySample]
	}
	return probeResult{mutation: m, request: req, response: resp}, nil
}

// waitForCallback polls d.callback.Observations for token, bounded by
// callbackMaxWait -- never a permanent goroutine, never unbounded
// polling, ctx-aware so cancellation stops the wait immediately (see
// docs/phase-3-25-ssrf-active-detection.md section 14). Copied
// verbatim in structure from internal/detectors/ssrf's own
// waitForCallback (Phase 3.4, already reviewed there).
func (d *Detector) waitForCallback(ctx context.Context, token string) ([]ssrf.Observation, error) {
	deadline := time.Now().Add(callbackMaxWait)
	for {
		obs, err := d.callback.Observations(ctx, token)
		if err != nil {
			return nil, err
		}
		if len(obs) > 0 {
			return obs, nil
		}
		if time.Now().After(deadline) {
			return nil, nil
		}
		timer := time.NewTimer(callbackPollInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
}

// locationFor maps t.ParameterLocation to the mutation.Location the
// probe's Mutation needs -- identical switch to
// internal/detectors/sqliactive/xssactive/idoractive's own.
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
