// Package traversal implements sakanner's fifth real vulnerability
// detector: path traversal / controlled LFI -- unsanitized path-like
// input reaching a file/resource lookup, allowing access outside an
// intended directory root. It implements detection.Detector
// (internal/detection, Phase 3.1) unchanged -- see
// docs/phase-3-6-path-traversal.md for the full design writeup and
// "How to implement a new detector" in docs/phase-3-1-detection-engine.md
// for the contract this follows.
//
// This package performs DETECTION only, and only against a small,
// operator-configured set of KNOWN traversal representations and their
// confirmation markers (TraversalCase) -- it never invents knowledge of
// what a target's protected resource is, never reads a file from the
// scanner's own filesystem (every "path" this package ever handles is
// data inside an HTTP request/response, never a local filesystem call),
// and never attempts a destructive request (only GET). See
// docs/phase-3-6-path-traversal.md "What this detector does not do."
package traversal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"strings"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "path-traversal"

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's bound
// (section 23's response-size limit).
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around matched evidence text in stored findings.
const evidenceFragmentRadius = 80

// maxVariantsPerCase bounds how many encoded representations of a
// single configured TraversalCase are ever tried -- traversalVariants
// already returns a small, fixed, deduplicated set, but this is a
// second, explicit ceiling (section 22's "limit... encoding variants")
// enforced regardless of what traversalVariants produces.
const maxVariantsPerCase = 8

// notFoundBaselineValue is a value this detector substitutes for the
// candidate's parameter to characterize "not found" behavior for THIS
// endpoint -- deliberately not traversal-shaped at all, and
// astronomically unlikely to collide with any real file a target
// happens to serve.
const notFoundBaselineValue = "sakannerTraversalBaseline-3f8c9a2e-does-not-exist.txt"

// pathLikeParameterNames is the exact, task-specified query-parameter
// name heuristic (section 5). See docs/phase-3-6-path-traversal.md
// "Candidate selection" for why parameter NAME plus operator-supplied
// TraversalCase knowledge is the only signal available today.
var pathLikeParameterNames = map[string]bool{
	"file": true, "filename": true, "filepath": true, "path": true,
	"file_path": true, "document": true, "document_path": true,
	"template": true, "resource": true, "download": true,
	"attachment": true, "image": true, "directory": true,
}

func isPathLikeParameterName(name string) bool {
	return pathLikeParameterNames[strings.ToLower(name)]
}

// Detector implements detection.Detector for path traversal.
type Detector struct {
	cases []TraversalCase
}

// New returns a ready-to-register Detector that tests for path
// traversal using cases. With no cases configured (including
// nil/empty), every Detect call returns OutcomeSkipped rather than
// doing anything, so a caller that constructs one anyway (e.g. while
// operator configuration is incomplete) fails safe. See
// docs/phase-3-6-path-traversal.md "Known traversal cases."
func New(cases []TraversalCase) *Detector {
	return &Detector{cases: cases}
}

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Path Traversal Detector",
		Category:             "broken_access_control",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		Prerequisites: []string{
			"at least 1 operator-configured TraversalCase (a known relative traversal path plus its confirmation marker) -- not wired into production yet, see docs/phase-3-6-path-traversal.md",
		},
		DefaultSeverity: models.SeverityHigh,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target whose parameter NAME looks path-like is ever a
// candidate. See docs/phase-3-6-path-traversal.md "Candidate
// selection."
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query" &&
		isPathLikeParameterName(t.Parameter)
}

// Detect implements detection.Detector. See docs/phase-3-6-path-traversal.md
// "Baseline and traversal probing" and "Confidence" for the full
// rationale.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if len(d.cases) == 0 {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	original := parameterValue(t)

	// The "legitimate access" reference: t.URL's already-discovered
	// value, unchanged. Recon found this URL working, so it's the
	// natural presumed-legitimate baseline -- the same pattern
	// xssreflected/sqli/ssrf/idor all use for their own baselines.
	legitBody, legitResp, err := probeRaw(ctx, x, t, t.URL)
	if err != nil {
		return detection.Result{}, fmt.Errorf("traversal: legitimate-access baseline probe: %w", err)
	}
	if !isAnalyzable(legitResp, legitBody) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if !looksAllowed(legitResp.StatusCode, legitBody) {
		// The endpoint doesn't even serve its own originally-discovered
		// value successfully -- nothing to use as a reference.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	// The "not found" reference: a deliberately nonexistent value,
	// substituted for the SAME parameter -- characterizes what "denied/
	// not found" looks like for this endpoint, distinct from "allowed."
	notFoundBody, notFoundResp, err := probe(ctx, x, t, notFoundBaselineValue)
	if err != nil {
		return detection.Result{}, fmt.Errorf("traversal: not-found baseline probe: %w", err)
	}

	var confirmed, suspicious []traversalAttempt
	for _, c := range d.cases {
		variants := traversalVariants(c.RelativePath)
		if len(variants) > maxVariantsPerCase {
			variants = variants[:maxVariantsPerCase]
		}
		for _, variant := range variants {
			body, resp, err := probe(ctx, x, t, variant)
			if err != nil {
				return detection.Result{}, fmt.Errorf("traversal: probe (%s): %w", variant, err)
			}
			if !looksAllowed(resp.StatusCode, body) {
				continue // correctly denied -- no evidence of a problem for this variant
			}
			attempt := traversalAttempt{traversalCase: c, variant: variant, body: body, resp: resp}
			if containsMarker(body, c.Marker) {
				confirmed = append(confirmed, attempt)
				break // this case is proven; no need to try remaining variants
			}
			// Strip each response's own injected value before comparing
			// (section 10 / the Phase 3.3 lesson, applied proactively):
			// an endpoint that merely ECHOES the requested value back
			// (e.g. "Requested file: <value>") must never look
			// "different from baseline" just because the two probes'
			// echoed strings differ from each other -- that difference
			// is an artifact of reflection, not evidence of anything.
			// variant may be an already-percent-encoded wire
			// representation (e.g. "%2e%2e/..."); a reflecting endpoint
			// echoes back what net/http's OWN query decoding produced
			// (e.g. "../..."), so strip the DECODED form -- stripPayload
			// additionally tries HTML/URL-re-escaped forms on top of
			// whatever it's given, covering an endpoint that re-encodes
			// on the way out too.
			strippedProbe := normalizeBody(stripPayload(body, decodedForm(variant)))
			strippedBaseline := normalizeBody(stripPayload(notFoundBody, decodedForm(notFoundBaselineValue)))
			if strippedProbe != strippedBaseline {
				// Allowed, and distinguishable from "not found" even
				// after removing the reflected value itself -- more
				// than "HTTP 200 alone" (section 9's forbidden weak
				// evidence), but the specific protected marker was never
				// confirmed.
				suspicious = append(suspicious, attempt)
			}
		}
	}

	if len(confirmed) == 0 && len(suspicious) == 0 {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, original, legitBody, legitResp, notFoundBody, notFoundResp, confirmed, suspicious),
	}}, nil
}

// traversalAttempt is one variant probe's result that was at least
// "allowed" (2xx, non-empty).
type traversalAttempt struct {
	traversalCase TraversalCase
	variant       string
	body          []byte
	resp          *nethttp.Response
}

// parameterValue extracts t.Parameter's discovered value from t.URL --
// the value this candidate was originally found with.
func parameterValue(t detection.Target) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Query().Get(t.Parameter)
}

// finding builds a models.Finding summarizing every confirmed and
// suspicious traversal attempt observed for this candidate. Like idor,
// this detector reports at most ONE finding per (endpoint, parameter)
// candidate, aggregating every attempt into that one finding's
// evidence, rather than one finding per payload/encoding -- see
// docs/phase-3-6-path-traversal.md "Deduplication" for why (Phase 3.1's
// dedup key has no payload/encoding field, and Phase 3.1 is not
// extended without a genuine defect).
func (d Detector) finding(t detection.Target, original string, legitBody []byte, legitResp *nethttp.Response, notFoundBody []byte, notFoundResp *nethttp.Response, confirmed, suspicious []traversalAttempt) models.Finding {
	best := confirmed
	tier := "confirmed"
	if len(best) == 0 {
		best = suspicious
		tier = "suspicious"
	}

	var reprs []string
	for _, a := range best {
		reprs = append(reprs, a.variant)
	}

	severity, confidence, reason := models.SeverityHigh, 0.55,
		fmt.Sprintf("traversal representation(s) %s were allowed (2xx, non-empty) and differ from this endpoint's own \"not found\" baseline, but the configured protected-resource marker was never confirmed in the response -- traversal-shaped access was observed but full confirmation is incomplete", strings.Join(reprs, ", "))
	if tier == "confirmed" {
		severity, confidence, reason = models.SeverityCritical, 0.9,
			fmt.Sprintf("traversal representation(s) %s returned the CONFIGURED PROTECTED-RESOURCE MARKER verbatim -- confirmed unauthorized access to a specific resource outside the intended root, not merely an allowed status code", strings.Join(reprs, ", "))
	}

	probeStatus := 0
	if best[0].resp != nil {
		probeStatus = best[0].resp.StatusCode
	}
	fragment := fragmentAround(best[0].body, best[0].traversalCase.Marker)
	if fragment == "" {
		fragment = fragmentAround(best[0].body, best[0].variant)
	}

	return models.Finding{
		VulnerabilityType: "path_traversal",
		Title:             "Path Traversal",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows a traversal-shaped value to reach a resource lookup that escapes the endpoint's intended root. Representation(s): %s.",
			t.Parameter, t.Path, strings.Join(reprs, ", "),
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Canonicalize the resolved path and verify it is still contained within the intended allowed root before using it, server-side, on every request -- never rely on blocklisting \"..\" substrings alone. Prefer an allowlist/ID-based lookup where practical (never constructing a filesystem path from client input at all), but containment verification on the fully-resolved path is the actual fix.",
		Evidence:          buildTraversalEvidence(t, original, legitBody, legitResp, notFoundBody, notFoundResp, best, probeStatus, fragment, tier, reason),
	}
}

// buildTraversalEvidence assembles this finding's evidence records: the
// legitimate-access baseline (legitBody/legitResp -- t.URL's own
// originally-discovered value, already used above to gate eligibility),
// the not-found baseline (notFoundBody/notFoundResp -- already used
// above to drive the confirmed/suspicious stripped-comparison split),
// the primary traversal probe (unchanged from before this phase), and
// any ADDITIONAL allowed variants beyond the first (best[1:]) that were
// already computed and evaluated but previously discarded entirely. See
// docs/phase-3-11-scan-orchestrator.md "Real evidence integration."
func buildTraversalEvidence(t detection.Target, original string, legitBody []byte, legitResp *nethttp.Response, notFoundBody []byte, notFoundResp *nethttp.Response, best []traversalAttempt, probeStatus int, fragment, tier, reason string) []models.Evidence {
	notFoundStatus := 0
	if notFoundResp != nil {
		notFoundStatus = notFoundResp.StatusCode
	}

	evidence := []models.Evidence{
		detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (parameter=%s, baseline=legitimate-access)", requestURLForEvidence(t, original), t.Parameter),
			Response:         fmt.Sprintf("status=%d", legitResp.StatusCode),
			StatusCode:       legitResp.StatusCode,
			Parameter:        t.Parameter,
			Payload:          original,
			ResponseFragment: fragmentAround(legitBody, original),
			Observation:      fmt.Sprintf("target=%s parameter=%s original=%s role=legitimate-access-baseline", t.Path, t.Parameter, original),
			Reason:           "the endpoint's own originally-discovered value, unchanged, establishes the presumed-legitimate reference every traversal variant below is judged against",
		}),
		detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (parameter=%s, baseline=not-found)", requestURLForEvidence(t, notFoundBaselineValue), t.Parameter),
			Response:         fmt.Sprintf("status=%d", notFoundStatus),
			StatusCode:       notFoundStatus,
			Parameter:        t.Parameter,
			Payload:          notFoundBaselineValue,
			ResponseFragment: fragmentAround(notFoundBody, notFoundBaselineValue),
			Observation:      fmt.Sprintf("target=%s parameter=%s role=not-found-baseline", t.Path, t.Parameter),
			Reason:           "a deliberately nonexistent value characterizes what \"denied/not found\" looks like for this endpoint, distinct from \"allowed\"",
		}),
		detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (parameter=%s)", requestURLForEvidence(t, best[0].variant), t.Parameter),
			Response:         fmt.Sprintf("status=%d", probeStatus),
			StatusCode:       probeStatus,
			Parameter:        t.Parameter,
			Payload:          best[0].variant,
			ResponseFragment: fragment,
			Observation: fmt.Sprintf(
				"target=%s parameter=%s original=%s probe=%s expected=denied actual=%d proof_marker_matched=%v",
				t.Path, t.Parameter, original, best[0].variant, probeStatus, tier == "confirmed",
			),
			Reason: reason,
		}),
	}

	for _, a := range best[1:] {
		status := 0
		if a.resp != nil {
			status = a.resp.StatusCode
		}
		af := fragmentAround(a.body, a.traversalCase.Marker)
		if af == "" {
			af = fragmentAround(a.body, a.variant)
		}
		evidence = append(evidence, detection.NewTypedRequestResponseEvidence(models.EvidenceKindProbe, "", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (parameter=%s)", requestURLForEvidence(t, a.variant), t.Parameter),
			Response:         fmt.Sprintf("status=%d", status),
			StatusCode:       status,
			Parameter:        t.Parameter,
			Payload:          a.variant,
			ResponseFragment: af,
			Observation: fmt.Sprintf(
				"target=%s parameter=%s original=%s probe=%s expected=denied actual=%d proof_marker_matched=%v",
				t.Path, t.Parameter, original, a.variant, status, containsMarker(a.body, a.traversalCase.Marker),
			),
			Reason: "an additional allowed traversal variant against the same candidate, evaluated the same way as the primary one above",
		}))
	}
	return evidence
}

// probe issues one GET request against t with t.Parameter's value
// replaced by rawValue -- rawValue is sent VERBATIM on the wire (see
// requestURL), never re-escaped, so an already-percent-encoded
// representation reaches the target's own decoder intact.
func probe(ctx context.Context, x *detection.Executor, t detection.Target, rawValue string) ([]byte, *nethttp.Response, error) {
	reqURL, err := requestURL(t, rawValue)
	if err != nil {
		return nil, nil, fmt.Errorf("build probe url: %w", err)
	}
	return probeRaw(ctx, x, t, reqURL)
}

// probeRaw issues one GET request against the literal reqURL --
// reqURL must already be t-relative (same host/scheme t.IP resolves
// to; Do's scope check is against t, not against reqURL's host, but
// every caller here always derives reqURL from t.URL, never from
// probe-response content or any other untrusted source, so it can
// never point anywhere Do wouldn't otherwise allow for t).
func probeRaw(ctx context.Context, x *detection.Executor, t detection.Target, reqURL string) ([]byte, *nethttp.Response, error) {
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build probe request: %w", err)
	}
	resp, err := x.Do(ctx, t, req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySample))
	if err != nil {
		return nil, nil, fmt.Errorf("read probe response: %w", err)
	}
	return body, resp, nil
}

// requestURL returns t.URL with t.Parameter's value replaced by
// rawValue, sent VERBATIM (never re-escaped) on the wire -- this is
// the ONLY place this package ever builds a request destination, and
// it only ever composes strings for an HTTP request; nothing here (or
// anywhere else in this package) ever calls a local filesystem API
// with any part of rawValue, t, or a probe response (section 21 -- see
// docs/phase-3-6-path-traversal.md "Scanner filesystem safety" and
// filesystem_safety_test.go).
func requestURL(t detection.Target, rawValue string) (string, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return "", fmt.Errorf("parse target URL: %w", err)
	}
	q := u.Query()
	q.Del(t.Parameter)
	rest := q.Encode()

	pair := t.Parameter + "=" + rawValue
	if rest != "" {
		u.RawQuery = pair + "&" + rest
	} else {
		u.RawQuery = pair
	}
	return u.String(), nil
}

// requestURLForEvidence is requestURL without the error return, for
// building the human-readable evidence line only -- falling back to
// t.URL verbatim if parsing somehow fails is safe here since this
// value is never used to issue a request.
func requestURLForEvidence(t detection.Target, rawValue string) string {
	s, err := requestURL(t, rawValue)
	if err != nil {
		return t.URL
	}
	return s
}

// decodedForm best-effort URL-decodes s (falling back to s unchanged
// if it isn't validly encoded) -- see the comment at its call site in
// Detect for why the DECODED form, not the wire form, is what a
// reflecting endpoint actually echoes back.
func decodedForm(s string) string {
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
}

// isAnalyzable reports whether a response is a content type this
// detector can reason about with plain byte/string comparison --
// text/*, JSON, or XML, never blindly-parsed binary content.
func isAnalyzable(resp *nethttp.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = nethttp.DetectContentType(body)
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml")
}

// fragmentAround returns a small window of body centered on needle --
// bounded evidence, never the full response. Returns "" if needle is
// empty or not found and body itself is empty.
func fragmentAround(body []byte, needle string) string {
	if needle == "" {
		return ""
	}
	idx := bytes.Index(body, []byte(needle))
	if idx < 0 {
		if len(body) == 0 {
			return ""
		}
		end := evidenceFragmentRadius * 2
		if end > len(body) {
			end = len(body)
		}
		return string(body[:end])
	}
	start := idx - evidenceFragmentRadius
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + evidenceFragmentRadius
	if end > len(body) {
		end = len(body)
	}
	return string(body[start:end])
}
