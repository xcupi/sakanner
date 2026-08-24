// Package sqliactive implements Phase 3.20's active SQL injection
// detector -- the second detector built on Phase 3.19's mutation-based
// active detection architecture, proving that a new detector can reuse
// the existing mutation, execution, authentication, identity, scope,
// evidence, correlation, and risk architecture without duplicating any
// of it. See docs/phase-3-20-sqli.md.
//
// This is a SECOND, independent SQL injection detector, deliberately
// coexisting with internal/detectors/sqli (Phase 3.3) rather than
// replacing it -- that detector keeps its own private requestURL/probe
// pair, its own full test suite, and its own lab ground-truth mapping,
// all unmodified. This detector's stable ID ("sqli-active") is
// distinct so both can be independently enabled/disabled.
//
// Detection only: error-based and boolean-based differential SQL
// injection via query and JSON-body parameters. Every payload is
// read-only (a control value, a syntax-breaking quote, or a
// tautology/contradiction pair) -- never a destructive statement, a
// stacked query, or an out-of-band callback. No time-based detection
// is implemented (see docs/phase-3-20-sqli.md section 4 for why).
package sqliactive

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "sqli-active"

// Probe payloads -- identical, deliberately, to
// internal/detectors/sqli's own already-reviewed set (Phase 3.3): a
// plain control value, a syntax-breaking quote, and a tautology/
// contradiction pair. Every one is read-only; none can plausibly
// execute a destructive statement.
const (
	baselineValue     = "1"
	errorProbePayload = "'"
	truePayload       = "1' OR '1'='1"
	falsePayload      = "1' AND '1'='2"
)

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's own
// established bound.
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// SQL injection.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "SQL Injection Detector (Active)",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		DefaultSeverity:      models.SeverityCritical,
	}
}

// Eligible implements detection.Detector -- identical shape to
// internal/detectors/xssactive's own: a query-location parameter on a
// GET endpoint, a JSON-body-location parameter on any method, a
// (Phase 3.21) form-location parameter on any method -- mirroring
// "body"'s own permissiveness, since a form-sourced endpoint's Method
// is already whatever the HTML form declared (GET forms use "query",
// never "form" -- see internal/parameters.addFormCandidates) -- or
// (Phase 3.23) a path-location parameter on any method: a path
// segment's mutability has nothing to do with HTTP method, unlike a
// GET-only query string.
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

// probeResult bundles one probe's mutation, request, and response --
// kept together so classification/evidence code never has to
// re-derive which mutation produced which response.
type probeResult struct {
	mutation mutation.Mutation
	request  mutation.Request
	response mutation.Response
}

// Detect implements detection.Detector. Four probes, all executed via
// x.ExecuteMutation -- the ONLY sanctioned request path (see
// docs/phase-3-20-sqli.md section 5). No detector-specific HTTP
// client, cookie jar, or scope decision exists anywhere in this
// package.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	// Phase 3.21/3.23: "form"/"path" are the minimum adapters those
	// phases add -- every other line in this file is unchanged (see
	// docs/phase-3-20-sqli.md section 6, docs/phase-3-23-path-parameters.md
	// section 4). "body" continues to mean a JSON request body (Phase
	// 3.20); "form" means an application/x-www-form-urlencoded one
	// (Phase 3.21); "path" means a URL path segment (Phase 3.23) --
	// BuildTargets has emitted them all as distinct ParameterLocation
	// values since their own phase.
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

	baseline, err := d.probe(ctx, x, original, loc, t, baselineValue)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqliactive: baseline probe: %w", err)
	}
	if baseline.response.Outcome != mutation.OutcomeSuccess {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	errProbe, err := d.probe(ctx, x, original, loc, t, errorProbePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqliactive: error probe: %w", err)
	}
	trueProbe, err := d.probe(ctx, x, original, loc, t, truePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqliactive: true-condition probe: %w", err)
	}
	falseProbe, err := d.probe(ctx, x, original, loc, t, falsePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqliactive: false-condition probe: %w", err)
	}

	sig := computeSignals(baseline, errProbe, trueProbe, falseProbe)
	tier, ok := classify(sig)
	if !ok {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, sig, tier, baseline, errProbe, trueProbe, falseProbe),
	}}, nil
}

// probe mutates original's target parameter to payload and executes it
// -- the ONLY way this package ever issues a request. Building the
// Mutation, applying it, and executing it are each a single call into
// Phase 3.17/3.19's own machinery; nothing here constructs an
// http.Request or a client of its own.
func (d Detector) probe(ctx context.Context, x *detection.Executor, original mutation.Request, loc mutation.Location, t detection.Target, payload string) (probeResult, error) {
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

// stripPayload removes every occurrence of payload from body -- raw,
// HTML-entity-encoded, and URL-encoded forms -- so a boolean-
// differential comparison is never confused by the payload's OWN text
// being reflected back verbatim (task section 9's "reflected payload"
// false-positive case). Independently re-derived from
// internal/detectors/sqli's own identical, already-reviewed technique.
func stripPayload(body []byte, payload string) []byte {
	s := string(body)
	for _, form := range []string{payload, html.EscapeString(payload), url.QueryEscape(payload)} {
		if form == "" {
			continue
		}
		s = strings.ReplaceAll(s, form, "")
	}
	return []byte(s)
}
