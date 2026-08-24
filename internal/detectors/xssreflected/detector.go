// Package xssreflected implements sakanner's first real vulnerability
// detector: reflected (non-persistent, non-DOM) cross-site scripting.
// It implements detection.Detector (internal/detection) unchanged --
// see docs/phase-3-2-reflected-xss.md for the full design writeup and
// "How to implement a new detector" in
// docs/phase-3-1-detection-engine.md for the contract this follows.
//
// This package detects ONLY reflected XSS: a GET query parameter whose
// value is echoed back into the HTML response without adequate
// encoding, immediately, in the same response. It does NOT detect
// stored XSS (a later, separate response), DOM-based XSS (client-side
// JavaScript sinks, never observable from response bodies alone), or
// any other injection class.
package xssreflected

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
const ID = "xss-reflected"

// reflectionMarker is the base string every probe looks for in a
// response. It contains no HTML metacharacters by itself and is
// distinctive enough that no real, unrelated page should ever contain
// it by accident -- matching the exact marker already documented in
// lab/ground-truth-vulnerabilities.yaml's expected_evidence
// fields for the reflected-XSS fixtures this detector is verified
// against.
const reflectionMarker = "sakannerXSSPROBE"

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe, matching the same bounded-sample discipline
// internal/http.Prober already uses for the exact same reason (never
// buffer an attacker- or target-controlled response without a cap).
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around a reflection point in stored evidence -- enough for a human
// reviewer to see the reflection in place, never a full response body.
const evidenceFragmentRadius = 80

// reflectionContext classifies WHERE in the HTML structure a reflection
// landed, determined from the plain-marker reflection probe's response
// (see classifyContext) -- never guessed from a payload-bearing probe,
// whose own metacharacters could otherwise be mistaken for surrounding
// structure.
type reflectionContext string

const (
	contextHTMLText      reflectionContext = "html_text"
	contextHTMLAttribute reflectionContext = "html_attribute"
	contextUnknown       reflectionContext = "unknown"
)

// Detector implements detection.Detector for reflected XSS.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:       ID,
		Name:     "Reflected XSS Detector",
		Category: "injection",
		// Only endpoint-kind targets carry a Parameter -- see
		// docs/phase-3-1-detection-engine.md "Target selection" for why
		// that's currently query-string-derived only, which is exactly
		// this detector's own input surface too (see "Input selection"
		// in docs/phase-3-2-reflected-xss.md).
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		// GET only, deliberately -- see docs/phase-3-2-reflected-xss.md
		// "Input selection" for why POST/form-body parameters are out of
		// scope for this phase (Phase 2's Endpoint model has no form
		// field names to test in the first place).
		SupportedMethods: []string{nethttp.MethodGet},
		DefaultSeverity:  models.SeverityHigh,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target is ever a candidate -- the engine's own
// Metadata-based pre-filter already enforces Kind/Method, so this only
// needs to add the ParameterLocation/non-empty-Parameter checks
// Metadata can't express declaratively.
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query"
}

// Detect implements detection.Detector. See docs/phase-3-2-reflected-xss.md
// "Probes" for the full rationale behind each of the (at most three)
// requests this makes.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	// --- 1. Reflection probe -------------------------------------------
	// Purpose: does the parameter's value appear in the response AT ALL.
	// A plain alphanumeric marker, no HTML metacharacters -- this alone
	// can never break or reveal HTML structure, so a positive/negative
	// result here is unambiguous and free of encoding questions. This is
	// also where the surrounding static template is classified into a
	// reflectionContext (see classifyContext), since the marker's own
	// characters can't be mistaken for structure the way a later,
	// metacharacter-bearing probe's payload could be.
	reflBody, reflResp, err := probe(ctx, x, t, reflectionMarker)
	if err != nil {
		return detection.Result{}, fmt.Errorf("xss-reflected: reflection probe: %w", err)
	}
	if !isHTMLLike(reflResp, reflBody) {
		// Section 20: an unsupported content type is NOT_APPLICABLE, not
		// a finding and not an error.
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if !bytes.Contains(reflBody, []byte(reflectionMarker)) {
		// Not reflected at all -- covers both "parameter has no effect"
		// and "response never echoes this parameter" fixtures. Nothing
		// further to check; reflection alone would not have been
		// sufficient evidence anyway, and here there isn't even that.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}
	reflCtx := classifyContext(reflBody, reflectionMarker)

	// --- 2. Context probe -----------------------------------------------
	// Purpose: does this specific position actually let HTML
	// metacharacters (<, >, ", ') survive unescaped -- i.e. is the
	// reflection DANGEROUS, not just present. Reflection alone is never
	// sufficient evidence (task requirement); this is the check that
	// turns "reflected" into "reflected AND unescaped."
	ctxPayload := "<" + reflectionMarker + `>"'`
	ctxBody, ctxResp, err := probe(ctx, x, t, ctxPayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("xss-reflected: context probe: %w", err)
	}
	dangerous := bytes.Contains(ctxBody, []byte(ctxPayload))
	if !dangerous {
		// Either HTML-entity-encoded, URL-encoded, filtered, or simply
		// not reflected in this second probe at all -- in every case,
		// no raw metacharacter breakout was observed, so there is
		// nothing exploitable to report.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}
	if reflCtx == contextUnknown {
		// Metacharacters survive unescaped, but this detector could not
		// reliably classify WHERE (e.g. inside an HTML comment, or some
		// other structure classifyContext doesn't recognize) -- per the
		// task's explicit confidence rubric, "reflection detected but
		// exploitability is uncertain" is LOW confidence, reported (not
		// silently dropped) so a human reviewer can look at the evidence
		// directly, but at reduced severity given the genuine placement
		// uncertainty.
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
			d.finding(t, reflCtx, models.SeverityMedium, 0.35, ctxPayload, ctxBody, ctxResp,
				"metacharacters (<, >, \", ') were reflected unescaped, but the surrounding HTML structure could not be reliably classified"),
		}}, nil
	}

	// --- 3. Validation probe ---------------------------------------------
	// Purpose: confirm a FULL, context-appropriate, structurally valid
	// executable payload -- not just a few loose metacharacters -- still
	// reflects verbatim. This is the strongest evidence tier and is only
	// attempted once the two cheaper probes above have already
	// established reflection AND danger, per "the detector should stop
	// once sufficient evidence has been established" / "avoid
	// unnecessarily aggressive payloads."
	validPayload := validationPayload(reflCtx)
	valBody, valResp, err := probe(ctx, x, t, validPayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("xss-reflected: validation probe: %w", err)
	}
	switch {
	case bytes.Contains(valBody, []byte(validPayload)):
		// Strong evidence: the full executable payload survived intact.
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
			d.finding(t, reflCtx, models.SeverityHigh, 0.95, validPayload, valBody, valResp,
				"a full, context-appropriate executable payload was reflected verbatim, unescaped"),
		}}, nil
	case bytes.Contains(valBody, []byte(reflectionMarker)):
		// The marker survived but the full structured payload did not --
		// something (partial filtering, a WAF-like transform) altered
		// it. The smaller context probe's own evidence still stands (raw
		// metacharacters did reflect there), so this is still reported,
		// just at reduced confidence: "reflection and suspicious context
		// detected but validation incomplete."
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
			d.finding(t, reflCtx, models.SeverityHigh, 0.6, validPayload, valBody, valResp,
				"the probe marker was reflected but the full validation payload was modified or partially filtered -- exploitability likely but not fully confirmed"),
		}}, nil
	default:
		// The larger, structurally-complete payload was fully
		// encoded/stripped even though the smaller context probe showed
		// raw metacharacters -- treat this as safe rather than reporting
		// on the earlier, now-contradicted evidence (e.g. a filter that
		// specifically targets `<script>`-shaped input but not bare
		// `<`/`"` characters in isolation).
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}
}

// finding builds a models.Finding for a confirmed reflection. Only the
// fields a detector is expected to set are populated here --
// DetectorID/Host/Port/URL/Method/AffectedEndpoint/ScanID/Source/timestamps
// are filled by the engine's normalizeFinding (see
// docs/phase-3-1-detection-engine.md "Finding model"), which never
// overwrites what's already set here.
func (d Detector) finding(t detection.Target, ctx reflectionContext, severity models.Severity, confidence float64, payload string, body []byte, resp *nethttp.Response, reason string) models.Finding {
	statusCode := 0
	var headers map[string]string
	if resp != nil {
		statusCode = resp.StatusCode
		headers = firstHeaders(resp.Header)
	}
	return models.Finding{
		VulnerabilityType: "reflected_xss",
		Title:             "Reflected Cross-Site Scripting (XSS)",
		Description: fmt.Sprintf(
			"The %q parameter on %s reflects attacker-controlled input into a %s context without adequate encoding, allowing arbitrary HTML/script to execute in a victim's browser session via a crafted link.",
			t.Parameter, t.Path, ctx,
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "HTML-encode all user-supplied input before embedding it in an HTML response. Use context-aware output encoding -- attribute encoding (and always quote attribute values) for attribute contexts, HTML entity encoding for text nodes -- and add a Content-Security-Policy as defense in depth.",
		Evidence: []models.Evidence{
			detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s", requestURL(t, payload)),
				Response:         fmt.Sprintf("HTTP %d", statusCode),
				StatusCode:       statusCode,
				Headers:          headers,
				Parameter:        t.Parameter,
				Payload:          payload,
				ResponseFragment: fragmentAround(body, payload, reflectionMarker),
				Observation:      fmt.Sprintf("context=%s", ctx),
				Reason:           reason,
			}),
		},
	}
}

// firstHeaders flattens resp.Header (which may carry multiple values
// per key) to one representative value per key, matching the same
// flattening internal/http.Prober already applies when persisting
// HTTPService.Headers -- evidence headers only need to show what a
// human reviewer would see, not a fully faithful multi-value dump.
func firstHeaders(h nethttp.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k := range h {
		out[k] = h.Get(k)
	}
	return out
}

// probe issues one GET request against t with t.Parameter set to
// payload, through x (the only sanctioned request path -- see
// detection.Executor's doc comment), and returns a bounded sample of
// the response body.
func probe(ctx context.Context, x *detection.Executor, t detection.Target, payload string) ([]byte, *nethttp.Response, error) {
	u, err := url.Parse(requestURL(t, payload))
	if err != nil {
		return nil, nil, fmt.Errorf("build probe URL: %w", err)
	}
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, u.String(), nil)
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

// requestURL returns t's URL with t.Parameter's value replaced by
// payload -- t.URL already carries whatever value Phase 2 originally
// discovered for every other query parameter, which is preserved.
func requestURL(t detection.Target, payload string) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		// t.URL came from BuildTargets, which only ever constructs valid
		// URLs -- this is unreachable in practice; fall back to the
		// unparsed string rather than panicking.
		return t.URL
	}
	q := u.Query()
	q.Set(t.Parameter, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// isHTMLLike reports whether a response should be treated as HTML this
// detector can reason about -- the response's own Content-Type header
// if present, or a body sniff (matching the same net/http content
// sniffing every other stage in this codebase implicitly relies on)
// when absent.
func isHTMLLike(resp *nethttp.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		return strings.Contains(strings.ToLower(ct), "html")
	}
	return strings.Contains(strings.ToLower(nethttp.DetectContentType(body)), "html")
}

// classifyContext determines where marker landed in body by looking at
// the HTML structure immediately preceding its first occurrence: if the
// nearest unclosed "<" (no matching ">" yet) ends in `="` or `='`,
// marker sits inside an attribute value; otherwise, if there is no
// unclosed tag at all at that point, marker sits in ordinary HTML text
// content. Anything else (e.g. inside a tag but not immediately after
// an attribute-value quote -- a bare tag name position, or inside an
// HTML comment) is reported as unknown rather than guessed.
func classifyContext(body []byte, marker string) reflectionContext {
	idx := bytes.Index(body, []byte(marker))
	if idx < 0 {
		return contextUnknown
	}
	before := string(body[:idx])
	lastLT := strings.LastIndex(before, "<")
	lastGT := strings.LastIndex(before, ">")
	insideTag := lastLT > lastGT

	switch {
	case insideTag && (strings.HasSuffix(before, `="`) || strings.HasSuffix(before, `='`)):
		return contextHTMLAttribute
	case !insideTag:
		return contextHTMLText
	default:
		return contextUnknown
	}
}

// validationPayload returns the third-probe payload appropriate for a
// confirmed reflection context: a complete script element for HTML
// text, or an attribute-breakout-plus-event-handler for HTML attribute
// context (both deliberately still deterministic, non-destructive, and
// scoped to proving script would run -- see docs/phase-3-2-reflected-xss.md
// "Controlled validation").
func validationPayload(ctx reflectionContext) string {
	if ctx == contextHTMLAttribute {
		return `x" onmouseover="` + reflectionMarker + `VALIDATE`
	}
	return "<script>" + reflectionMarker + "VALIDATE</script>"
}

// fragmentAround returns a small window of body centered on payload (or
// marker, if payload itself isn't found verbatim) -- bounded evidence,
// never the full response, per "avoid storing unnecessary full
// responses."
func fragmentAround(body []byte, payload, marker string) string {
	idx := bytes.Index(body, []byte(payload))
	needleLen := len(payload)
	if idx < 0 {
		idx = bytes.Index(body, []byte(marker))
		needleLen = len(marker)
	}
	if idx < 0 {
		return ""
	}
	start := idx - evidenceFragmentRadius
	if start < 0 {
		start = 0
	}
	end := idx + needleLen + evidenceFragmentRadius
	if end > len(body) {
		end = len(body)
	}
	return string(body[start:end])
}
