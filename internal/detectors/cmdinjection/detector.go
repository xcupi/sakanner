// Package cmdinjection implements sakanner's sixth real vulnerability
// detector: OS command injection through HTTP parameters -- unsanitized
// input reaching shell command construction, allowing arbitrary
// command execution on the target. It implements detection.Detector
// (internal/detection, Phase 3.1) unchanged -- see
// docs/phase-3-7-command-injection.md for the full design writeup and
// "How to implement a new detector" in docs/phase-3-1-detection-engine.md
// for the contract this follows.
//
// This package performs DETECTION only, via a self-generated,
// unpredictable per-probe correlation token: it injects
// "<separator> <lab-only fake command name> <token>" and treats a
// response as confirmed ONLY if it contains the exact constant marker
// prefix immediately followed by that EXACT token -- never a bare
// substring match, never a stale or cross-probe token, never a
// reflected copy of the injected text itself. See "What this detector
// does not do" in docs/phase-3-7-command-injection.md.
//
// CRITICAL SAFETY PROPERTY: this package never constructs a local
// shell command, never imports "os/exec", and never interprets target
// input, a target URL, or a target response as anything other than
// HTTP request/response data. See "Scanner shell isolation" in
// docs/phase-3-7-command-injection.md and shell_isolation_test.go.
package cmdinjection

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "command-injection"

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's bound.
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around matched evidence text in stored findings.
const evidenceFragmentRadius = 80

// commandLikeParameterNames is the exact, task-specified query-
// parameter name heuristic (section 6). See
// docs/phase-3-7-command-injection.md "Candidate selection."
var commandLikeParameterNames = map[string]bool{
	"host": true, "hostname": true, "ip": true, "address": true,
	"domain": true, "command": true, "cmd": true, "exec": true,
	"executable": true, "program": true, "file": true, "path": true,
	"target": true, "query": true,
}

func isCommandLikeParameterName(name string) bool {
	return commandLikeParameterNames[strings.ToLower(name)]
}

// Detector implements detection.Detector for OS command injection.
// Unlike ssrf/idor/traversal, it needs no constructor-injected,
// operator-supplied dependency: its correlation mechanism (a freshly
// generated per-probe token) is entirely self-contained, and the
// lab-recognized command name is a fixed, safe, public convention --
// not sensitive, production-specific knowledge. See
// docs/phase-3-7-command-injection.md "Why this detector needs no
// external configuration."
type Detector struct{}

// New returns a ready-to-register Detector.
func New() *Detector {
	return &Detector{}
}

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Command Injection Detector",
		Category:             "injection",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		DefaultSeverity:      models.SeverityHigh,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target whose parameter NAME looks command-like is ever a
// candidate. See docs/phase-3-7-command-injection.md "Candidate
// selection."
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query" &&
		isCommandLikeParameterName(t.Parameter)
}

// Detect implements detection.Detector. See docs/phase-3-7-command-injection.md
// "Controlled probes" and "Execution verification" for the full
// rationale.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	// Legitimate-access reference: t.URL's already-discovered value,
	// unchanged -- the same pattern every sibling detector uses for its
	// own baseline. Recorded for evidence ("BASELINE: normal behavior",
	// section 16) and as a basic reachability/analyzability gate.
	legitBody, legitResp, err := probeRaw(ctx, x, t, t.URL)
	if err != nil {
		return detection.Result{}, fmt.Errorf("cmdinjection: legitimate-access baseline probe: %w", err)
	}
	if !isAnalyzable(legitResp, legitBody) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if !looksAllowed(legitResp.StatusCode, legitBody) {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	for _, variant := range commandVariants() {
		token := uuid.NewString()
		probeValue := fmt.Sprintf(variant.template, token)

		body, resp, err := probe(ctx, x, t, probeValue)
		if err != nil {
			return detection.Result{}, fmt.Errorf("cmdinjection: probe (%s): %w", variant.name, err)
		}

		expected := markerPrefix + token
		if bytes.Contains(body, []byte(expected)) {
			// Exact per-probe correlation confirmed -- see
			// docs/phase-3-7-command-injection.md "Confidence" for why
			// this alone is airtight evidence and why no weaker tier is
			// fabricated.
			return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
				d.finding(t, legitBody, legitResp, variant, probeValue, token, resp.StatusCode, body),
			}}, nil
		}
	}

	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

// finding builds a models.Finding for a single confirmed variant. This
// detector stops at the first confirmed variant (see Detect) and
// therefore never needs to aggregate across multiple attempts the way
// idor/traversal do.
func (d Detector) finding(t detection.Target, legitBody []byte, legitResp *nethttp.Response, variant commandVariant, probeValue, token string, statusCode int, body []byte) models.Finding {
	fragment := fragmentAround(body, markerPrefix+token)

	return models.Finding{
		VulnerabilityType: "command_injection",
		Title:             "OS Command Injection",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows a shell-metacharacter-prefixed value to reach command execution. A freshly generated, unpredictable correlation token injected via the %s representation was echoed back through confirmed execution, not reflection.",
			t.Parameter, t.Path, variant.name,
		),
		Severity:          models.SeverityCritical,
		Confidence:        0.95,
		AffectedParameter: t.Parameter,
		Remediation:       "Never pass user-controlled input to a shell or command interpreter. Use language-level APIs that execute a fixed program with an argument LIST (never a concatenated/interpolated command string), or an allowlist of permitted values, so shell metacharacters can never change what gets executed.",
		Evidence: []models.Evidence{
			// The legitimate-access reference this detector already
			// fetches and uses as an eligibility gate (isAnalyzable/
			// looksAllowed above) -- captured as its own record instead of
			// being discarded once that gate passes. See
			// docs/phase-3-11-scan-orchestrator.md "Real evidence
			// integration."
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s (parameter=%s, baseline=legitimate-access)", t.URL, t.Parameter),
				Response:         fmt.Sprintf("status=%d", legitResp.StatusCode),
				StatusCode:       legitResp.StatusCode,
				Parameter:        t.Parameter,
				ResponseFragment: fragmentAround(legitBody, ""),
				Observation:      fmt.Sprintf("target=%s parameter=%s role=legitimate-access-baseline", t.Path, t.Parameter),
				Reason:           "the endpoint's own originally-discovered value, unchanged, establishes reachability and normal behavior before any probe is attempted",
			}),
			detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s (parameter=%s, probe=%s)", requestURLForEvidence(t, probeValue), t.Parameter, variant.name),
				Response:         fmt.Sprintf("status=%d", statusCode),
				StatusCode:       statusCode,
				Parameter:        t.Parameter,
				Payload:          probeValue,
				ResponseFragment: fragment,
				Observation: fmt.Sprintf(
					"target=%s parameter=%s probe=%s expected=input_treated_as_data actual=controlled_command_execution_occurred proof=%s",
					t.Path, t.Parameter, variant.name, markerPrefix+token,
				),
				Reason: fmt.Sprintf(
					"the response contains %q -- the exact constant marker prefix immediately followed by THIS probe's own freshly generated, unpredictable token -- which could only appear if the injected value was interpreted as a command, not merely reflected, stored, or matched against unrelated static content",
					markerPrefix+token,
				),
			}),
		},
	}
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

// probeRaw issues one GET request against the literal reqURL, derived
// only from t.URL/t.Parameter -- never from probe-response content or
// any other untrusted source. This function, like every other function
// in this package, only ever builds an HTTP request; it never invokes
// a local shell or any local command-execution API (section 20 -- see
// shell_isolation_test.go).
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
// rawValue, sent VERBATIM (never re-escaped) on the wire -- the ONLY
// place this package ever builds a request destination.
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
// building the human-readable evidence line only.
func requestURLForEvidence(t detection.Target, rawValue string) string {
	s, err := requestURL(t, rawValue)
	if err != nil {
		return t.URL
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
// bounded evidence, never the full response, and NEVER arbitrary
// command output, environment variables, or system information
// (section 16) -- only ever a snippet around the detector's own
// constant marker + token.
func fragmentAround(body []byte, needle string) string {
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
