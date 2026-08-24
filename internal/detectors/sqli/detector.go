// Package sqli implements sakanner's second real vulnerability
// detector: SQL injection, detected via a bounded baseline + error +
// boolean-differential probe sequence. It implements
// detection.Detector (internal/detection, Phase 3.1) unchanged -- see
// docs/phase-3-3-sqli.md for the full design writeup and "How to
// implement a new detector" in docs/phase-3-1-detection-engine.md for
// the contract this follows.
//
// This package performs DETECTION only. It never attempts data
// extraction, database/table enumeration, credential dumping, or any
// destructive statement (DROP/DELETE/UPDATE/INSERT/ALTER/CREATE) --
// every probe payload is a read-only boolean condition or a single
// syntax-breaking character, chosen to reveal behavior, never to
// change or retrieve data. See docs/phase-3-3-sqli.md "What this
// detector does not do."
package sqli

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
const ID = "sqli"

// Probe payloads. See docs/phase-3-3-sqli.md "Probes" for why each one
// exists and why exactly these four (never more) are sent per
// candidate parameter.
const (
	// baselineValue is a plain, syntactically inert control value --
	// what a normal, non-malicious request looks like. Differential
	// comparison has nothing to compare against without it.
	baselineValue = "1"
	// errorProbePayload is a single unbalanced quote -- the smallest
	// possible syntax-breaking input, chosen specifically because it
	// cannot itself alter query semantics (unlike the boolean payloads
	// below), only reveal whether unescaped input reaches SQL syntax at
	// all.
	errorProbePayload = "'"
	// trueProbePayload is a tautology: syntactically valid, and (if
	// concatenated unsanitized into a query) always evaluates true.
	trueProbePayload = "1' OR '1'='1"
	// falseProbePayload is a contradiction: syntactically valid, and
	// (under the same conditions) always evaluates false. Paired with
	// trueProbePayload, this is the controlled "condition A vs.
	// condition B" comparison the differential signal is built from.
	falseProbePayload = "1' AND '1'='2"
)

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches internal/http.Prober's and
// xssreflected's own bound, for the same reason (never buffer an
// attacker- or target-controlled response without a cap).
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around a matched error signature in stored evidence.
const evidenceFragmentRadius = 80

// Detector implements detection.Detector for SQL injection.
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector { return &Detector{} }

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "SQL Injection Detector",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		DefaultSeverity:      models.SeverityCritical,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target is ever a candidate -- see docs/phase-3-3-sqli.md
// "Target selection" for why (the same query-string-derived-only
// parameter surface xssreflected already relies on).
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query"
}

// signals is the correlated evidence gathered from one candidate's 4
// probes, computed once and then mapped to a confidence/severity tier
// by classify. Keeping this as a separate, directly-testable struct
// (rather than inlining the decision logic into Detect) is what lets
// confidence calculation be unit-tested against synthetic inputs
// without needing an HTTP server.
type signals struct {
	errorFamily     string // "" if no database error signature matched anywhere relevant
	errorIsSpecific bool   // true if errorFamily is a named DB family, not just "generic"
	booleanDiff     bool   // true/false probes produced meaningfully different (normalized) responses
}

// Detect implements detection.Detector. See docs/phase-3-3-sqli.md
// "Probes" and "Confidence" for the full rationale.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	baseline, baseResp, err := probe(ctx, x, t, baselineValue)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqli: baseline probe: %w", err)
	}
	if !isAnalyzable(baseResp, baseline) {
		// Section 28: an unsupported content type is NOT_APPLICABLE,
		// not a finding and not an error.
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	errBody, errResp, err := probe(ctx, x, t, errorProbePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqli: error probe: %w", err)
	}
	trueBody, trueResp, err := probe(ctx, x, t, trueProbePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqli: boolean-true probe: %w", err)
	}
	falseBody, falseResp, err := probe(ctx, x, t, falseProbePayload)
	if err != nil {
		return detection.Result{}, fmt.Errorf("sqli: boolean-false probe: %w", err)
	}

	sig := computeSignals(baseline, errBody, trueBody, falseBody)

	tier, ok := classify(sig)
	if !ok {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, sig, tier, baseline, baseResp, errBody, errResp, trueBody, trueResp, falseBody, falseResp),
	}}, nil
}

// computeSignals correlates the 4 probe responses into the evidence
// classify decides on. The error signal is deliberately correlated
// against baseline BEFORE being trusted: an endpoint that already
// shows the same database-error-shaped text for a plain, benign
// request (a generically-misbehaving endpoint, or static content that
// happens to mention "database error") gives the probe's matching
// error zero additional weight -- see docs/phase-3-3-sqli.md "Error-
// based detection" for why this is required, not optional, false-
// positive prevention.
func computeSignals(baseline, errBody, trueBody, falseBody []byte) signals {
	baselineFamily, baselineMatched := matchDBError(string(baseline))
	errFamily, errMatched := matchDBError(string(errBody))

	var sig signals
	if errMatched && !(baselineMatched && baselineFamily == errFamily) {
		sig.errorFamily = errFamily
		sig.errorIsSpecific = errFamily != "generic"
	}

	// Strip each body's OWN probe payload (raw, HTML-entity-encoded, and
	// URL-encoded forms) before comparing -- an endpoint that simply
	// ECHOES the parameter back (a reflected-XSS-shaped page, an open
	// redirect's auto-generated "Found" body, a "page not found: X"
	// message) will otherwise show a textual difference between the
	// true- and false-condition responses for the trivial reason that
	// the two PAYLOADS themselves differ, with no SQL behavior involved
	// at all. See docs/phase-3-3-sqli.md "Differential detection" for
	// the false positives this was found to produce before this
	// stripping step existed, and TestComputeSignals_* for the
	// regression coverage.
	trueStripped := stripPayload(trueBody, trueProbePayload)
	falseStripped := stripPayload(falseBody, falseProbePayload)
	sig.booleanDiff = normalizeBody(trueStripped) != normalizeBody(falseStripped)
	return sig
}

// confidenceTier names the four possible outcomes classify can reach.
type confidenceTier struct {
	severity   models.Severity
	confidence float64
	reason     string
}

// classify maps correlated signals onto exactly the HIGH/MEDIUM/LOW
// confidence rubric docs/phase-3-3-sqli.md documents, returning ok=false
// when there is insufficient evidence for any finding at all --
// "reflection alone" (here, error text alone with no corroboration, or
// a bare boolean flicker with no error) still gets reported, but never
// at high confidence without either multiple signals or a proven
// behavioral difference.
func classify(sig signals) (confidenceTier, bool) {
	switch {
	case sig.errorIsSpecific && sig.booleanDiff:
		return confidenceTier{models.SeverityCritical, 0.95, "a database-family-specific error signature AND a consistent boolean true/false differential were both observed -- multiple independent signals"}, true
	case sig.booleanDiff:
		return confidenceTier{models.SeverityCritical, 0.75, "a controlled true-condition and false-condition probe produced a consistent, meaningful behavioral difference (normalized) -- confirmed data-exposure differential, independent of any error text"}, true
	case sig.errorIsSpecific:
		return confidenceTier{models.SeverityHigh, 0.55, fmt.Sprintf("a %s-family database error signature was observed for the syntax-breaking probe but not for the baseline -- a strong indication, but the boolean differential probes did not independently confirm it", sig.errorFamily)}, true
	case sig.errorFamily == "generic":
		return confidenceTier{models.SeverityMedium, 0.3, "only generic, cross-family database-error-shaped wording was observed, and the boolean differential probes did not confirm it -- a weak indication only"}, true
	default:
		return confidenceTier{}, false
	}
}

// finding builds a models.Finding for a confirmed signal set. Only the
// fields a detector is expected to set are populated here --
// DetectorID/Host/Port/URL/Method/AffectedEndpoint/ScanID/Source/timestamps
// are filled by the engine's normalizeFinding (Phase 3.1), which never
// overwrites what's already set here.
func (d Detector) finding(t detection.Target, sig signals, tier confidenceTier, baseline []byte, baseResp *nethttp.Response, errBody []byte, errResp *nethttp.Response, trueBody []byte, trueResp *nethttp.Response, falseBody []byte, falseResp *nethttp.Response) models.Finding {
	signalDesc := "boolean differential"
	if sig.errorFamily != "" {
		signalDesc = fmt.Sprintf("%s (error family: %s)", signalDesc, sig.errorFamily)
		if !sig.booleanDiff {
			signalDesc = fmt.Sprintf("database error (family: %s)", sig.errorFamily)
		}
	}

	fragment := fragmentAround(errBody, errorProbePayload)
	if fragment == "" {
		fragment = fragmentAround(trueBody, trueProbePayload)
	}

	_, baselineHadErrorSignature := matchDBError(string(baseline))

	return models.Finding{
		VulnerabilityType: "sql_injection",
		Title:             "SQL Injection",
		Description: fmt.Sprintf(
			"The %q parameter on %s appears to reach a SQL query without adequate sanitization, based on %s. This may allow an attacker to alter query logic, bypass application checks, or access data outside the intended scope.",
			t.Parameter, t.Path, signalDesc,
		),
		Severity:          tier.severity,
		Confidence:        tier.confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Use parameterized queries / prepared statements (or an ORM that does so) for every database query built from user input. Never concatenate untrusted input directly into SQL. Apply least-privilege database credentials and disable verbose database error output in production responses.",
		Evidence: []models.Evidence{
			// The unmodified control request/response this detector already
			// fetches and consults (computeSignals correlates the error
			// probe against it, see the "Error-based detection" doc
			// comment above) -- captured as its own record instead of only
			// being folded into the combined probe summary below. See
			// docs/phase-3-11-scan-orchestrator.md "Real evidence
			// integration."
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s", requestURL(t, baselineValue)),
				Response:         fmt.Sprintf("HTTP %d", statusOf(baseResp)),
				StatusCode:       statusOf(baseResp),
				Parameter:        t.Parameter,
				Payload:          baselineValue,
				ResponseFragment: fragmentAround(baseline, baselineValue),
				Observation:      fmt.Sprintf("baseline_status=%d baseline_error_signature=%v", statusOf(baseResp), baselineHadErrorSignature),
				Reason:           "a plain, syntactically inert control value establishes what a normal, non-malicious request to this parameter looks like, so the probes below can be judged against it rather than in isolation",
			}),
			detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s (baseline=%q, error_probe=%q, true_probe=%q, false_probe=%q)", requestURL(t, "{value}"), baselineValue, errorProbePayload, trueProbePayload, falseProbePayload),
				Response:         fmt.Sprintf("baseline=%d error_probe=%d true_probe=%d false_probe=%d", statusOf(baseResp), statusOf(errResp), statusOf(trueResp), statusOf(falseResp)),
				StatusCode:       statusOf(errResp),
				Parameter:        t.Parameter,
				Payload:          strings.Join([]string{errorProbePayload, trueProbePayload, falseProbePayload}, " | "),
				ResponseFragment: fragment,
				Observation:      fmt.Sprintf("error_family=%q boolean_differential=%v", sig.errorFamily, sig.booleanDiff),
				Reason:           tier.reason,
			}),
		},
	}
}

func statusOf(resp *nethttp.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
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
		// URLs -- unreachable in practice; fall back to the unparsed
		// string rather than panicking.
		return t.URL
	}
	q := u.Query()
	q.Set(t.Parameter, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// isAnalyzable reports whether a response is a content type this
// detector can reason about with plain byte/string comparison --
// text/*, JSON, or XML. Unlike xssreflected (which needs HTML
// specifically), SQL error/differential evidence can appear in any
// textual response shape, so this is deliberately broader -- but still
// excludes actual binary content (images, archives, ...), which is
// never blindly parsed.
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
// bounded evidence, never the full response, per "do not store
// unnecessarily large responses."
func fragmentAround(body []byte, needle string) string {
	idx := bytes.Index(body, []byte(needle))
	if idx < 0 {
		// needle (a payload) may not appear verbatim in an error/
		// differential response -- fall back to a leading sample so
		// there is still SOME evidence text, bounded the same way.
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
