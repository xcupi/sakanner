// Package idor implements sakanner's fourth real vulnerability
// detector: IDOR (Insecure Direct Object Reference) / BOLA (Broken
// Object Level Authorization) -- an object-level authorization failure
// where one authorization context can access another context's
// resource without authorization. It implements detection.Detector
// (internal/detection, Phase 3.1) unchanged -- see
// docs/phase-3-5-idor-bola.md for the full design writeup and "How to
// implement a new detector" in docs/phase-3-1-detection-engine.md for
// the contract this follows.
//
// This package performs DETECTION only, and only for object references
// whose OWNERSHIP is already known via operator-supplied configuration
// (AuthContext.OwnsResourceIDs) -- it never infers ownership from
// nothing (see AuthContext's doc comment), never attempts to establish
// or bypass authentication, and never performs a destructive request
// (only GET). See docs/phase-3-5-idor-bola.md "What this detector does
// not detect."
package idor

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
const ID = "idor"

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's bound.
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around matched evidence text in stored findings.
const evidenceFragmentRadius = 80

// objectReferenceParameterNames is the exact, task-specified query-
// parameter name heuristic (section 5). See docs/phase-3-5-idor-bola.md
// "Candidate selection" for why parameter NAME plus operator-supplied
// ownership is the only signal available today.
var objectReferenceParameterNames = map[string]bool{
	"id": true, "user_id": true, "account_id": true,
	"order_id": true, "document_id": true, "resource_id": true,
}

func isObjectReferenceParameterName(name string) bool {
	return objectReferenceParameterNames[strings.ToLower(name)]
}

// Detector implements detection.Detector for IDOR/BOLA.
type Detector struct {
	contexts []AuthContext
}

// New returns a ready-to-register Detector that tests object-level
// authorization using contexts. At least 2 contexts are required for
// any cross-context comparison to be possible at all -- with fewer
// than 2 (including nil/empty), every Detect call returns
// OutcomeSkipped rather than doing anything, so a caller that
// constructs one anyway (e.g. while operator configuration is
// incomplete) fails safe. See docs/phase-3-5-idor-bola.md
// "Authorization contexts."
func New(contexts []AuthContext) *Detector {
	return &Detector{contexts: contexts}
}

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "IDOR / BOLA Detector",
		Category:             "broken_access_control",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		Prerequisites: []string{
			"at least 2 operator-configured AuthContext values (synthetic pre-authenticated identities) -- not wired into production yet, see docs/phase-3-5-idor-bola.md",
			"operator-supplied resource-ownership ground truth (AuthContext.OwnsResourceIDs) -- this detector never infers ownership",
		},
		DefaultSeverity: models.SeverityCritical,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target whose parameter NAME looks like an object reference
// is ever a candidate. See docs/phase-3-5-idor-bola.md "Candidate
// selection."
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query" &&
		isObjectReferenceParameterName(t.Parameter)
}

// Detect implements detection.Detector. See docs/phase-3-5-idor-bola.md
// "Cross-resource testing" and "Confidence" for the full rationale.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if len(d.contexts) < 2 {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	id := parameterValue(t)
	if id == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	owner := d.ownerOf(id)
	if owner == nil {
		// Section 9: ownership unknown -> NOT_APPLICABLE, never a guess.
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	ownerBody, ownerResp, err := probeAs(ctx, x, t, *owner)
	if err != nil {
		return detection.Result{}, fmt.Errorf("idor: owner baseline probe: %w", err)
	}
	if !isAnalyzable(ownerResp, ownerBody) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if !looksAllowed(ownerResp.StatusCode, ownerBody) {
		// The configured owner can't even access their own resource --
		// nothing to establish a comparison baseline from.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}
	if !isResourceSpecific(ownerBody, id) {
		// The response doesn't vary by resource identifier at all (a
		// generic/constant body) -- never trustworthy evidence, no
		// matter what a cross-context request returns. See
		// normalize.go's isResourceSpecific doc comment.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	var crosses []crossAttempt
	for _, other := range d.contexts {
		if other.ID == owner.ID {
			continue
		}
		otherBody, otherResp, err := probeAs(ctx, x, t, other)
		if err != nil {
			return detection.Result{}, fmt.Errorf("idor: cross-context probe (%s): %w", other.ID, err)
		}
		if !looksAllowed(otherResp.StatusCode, otherBody) {
			continue // correctly denied -- no evidence of a problem for this context
		}
		crosses = append(crosses, crossAttempt{
			context: other, body: otherBody, resp: otherResp,
			matchesOwner: normalizeBody(otherBody) == normalizeBody(ownerBody),
		})
	}

	if len(crosses) == 0 {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, id, *owner, ownerBody, ownerResp, crosses),
	}}, nil
}

// crossAttempt is one other-than-owner context's result for the same
// resource identifier.
type crossAttempt struct {
	context      AuthContext
	body         []byte
	resp         *nethttp.Response
	matchesOwner bool
}

// ownerOf returns the configured context that owns id, or nil if none
// does.
func (d Detector) ownerOf(id string) *AuthContext {
	for i := range d.contexts {
		if d.contexts[i].Owns(id) {
			return &d.contexts[i]
		}
	}
	return nil
}

// parameterValue extracts t.Parameter's discovered value from t.URL --
// the specific resource identifier this candidate is testing.
func parameterValue(t detection.Target) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Query().Get(t.Parameter)
}

// finding builds a models.Finding summarizing every confirmed cross-
// context access observed for this candidate. This detector reports at
// most ONE finding per (endpoint, parameter) candidate, aggregating
// every confirmed cross-context access into that one finding's
// evidence, rather than one finding per direction/context-pair --
// because Phase 3.1's existing dedup key (host + port + endpoint +
// method + parameter + type) has no resource-identifier or
// authorization-context field to distinguish multiple directions as
// logically separate findings, and Phase 3.5 is instructed not to
// extend the framework without a genuine defect. See
// docs/phase-3-5-idor-bola.md "Deduplication" for the full rationale.
func (d Detector) finding(t detection.Target, id string, owner AuthContext, ownerBody []byte, ownerResp *nethttp.Response, crosses []crossAttempt) models.Finding {
	confirmed := false // at least one cross context's body matches the owner's baseline closely
	var names []string
	for _, c := range crosses {
		names = append(names, c.context.ID)
		if c.matchesOwner {
			confirmed = true
		}
	}

	severity, confidence, reason := models.SeverityHigh, 0.55,
		fmt.Sprintf("authorization context(s) %s received a 2xx, non-empty response for a resource owned by %q, but the response did not closely match the owner's own baseline -- access was observed but full protected-resource confirmation is incomplete", strings.Join(names, ", "), owner.ID)
	if confirmed {
		severity, confidence, reason = models.SeverityCritical, 0.9,
			fmt.Sprintf("authorization context(s) %s received the SAME response (after normalization) that owner %q receives for their own resource %q -- confirmed unauthorized access to a specific protected object, not merely a matching status code", strings.Join(names, ", "), owner.ID, id)
	}

	fragment := fragmentAround(crosses[0].body, id)
	crossStatus := 0
	if crosses[0].resp != nil {
		crossStatus = crosses[0].resp.StatusCode
	}

	return models.Finding{
		VulnerabilityType: "idor",
		Title:             "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)",
		Description: fmt.Sprintf(
			"The %q parameter on %s allows an authorization context other than the resource's owner (%q) to access it. Authorization context(s) affected: %s.",
			t.Parameter, t.Path, owner.ID, strings.Join(names, ", "),
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Verify object ownership (authenticated_user == resource.owner) on every request that accesses a specific object, server-side, before returning it -- never rely on the client only requesting IDs it's supposed to have. Prefer non-guessable, per-user-scoped references where practical, but ownership verification is the actual fix, not obscurity.",
		Evidence:          buildIDOREvidence(t, id, owner, ownerBody, ownerResp, crosses, names, fragment, crossStatus, confirmed, reason),
	}
}

// buildIDOREvidence assembles this finding's evidence records: the
// owner's own successful access (the reference every cross-context
// response is diffed against -- already captured as ownerBody/ownerResp
// and used in the matchesOwner comparison above, now recorded as its
// own EvidenceKindBaseline item instead of only being folded into the
// combined summary), the primary confirming cross-context probe
// (unchanged from before this phase), and any ADDITIONAL cross-context
// attempts beyond the first (crosses[1:]) that were already computed
// and evaluated but previously discarded entirely. See
// docs/phase-3-11-scan-orchestrator.md "Real evidence integration."
func buildIDOREvidence(t detection.Target, id string, owner AuthContext, ownerBody []byte, ownerResp *nethttp.Response, crosses []crossAttempt, names []string, fragment string, crossStatus int, confirmed bool, reason string) []models.Evidence {
	evidence := []models.Evidence{
		detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (as %s)", requestURL(t, id), owner.ID),
			Response:         fmt.Sprintf("HTTP %d", ownerResp.StatusCode),
			StatusCode:       ownerResp.StatusCode,
			Parameter:        t.Parameter,
			Payload:          id,
			ResponseFragment: fragmentAround(ownerBody, id),
			Observation:      fmt.Sprintf("who=%s what=%s role=owner", owner.ID, id),
			Reason:           "the resource owner's own successful access establishes the reference response every cross-context attempt below is compared against",
		}),
		detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (as %s)", requestURL(t, id), strings.Join(names, ",")),
			Response:         fmt.Sprintf("owner(%s)=%d cross(%s)=%d", owner.ID, ownerResp.StatusCode, names[0], crossStatus),
			StatusCode:       crossStatus,
			Parameter:        t.Parameter,
			Payload:          id,
			ResponseFragment: fragment,
			Observation: fmt.Sprintf(
				"who=%s what=%s owner=%s expected=denied actual=%s proof_matches_owner_baseline=%v",
				strings.Join(names, ","), id, owner.ID, nethttp.StatusText(crossStatus), confirmed,
			),
			Reason: reason,
		}),
	}

	for _, c := range crosses[1:] {
		status := 0
		if c.resp != nil {
			status = c.resp.StatusCode
		}
		evidence = append(evidence, detection.NewTypedRequestResponseEvidence(models.EvidenceKindProbe, "", "", detection.RequestResponseEvidence{
			Request:          fmt.Sprintf("GET %s (as %s)", requestURL(t, id), c.context.ID),
			Response:         fmt.Sprintf("HTTP %d", status),
			StatusCode:       status,
			Parameter:        t.Parameter,
			Payload:          id,
			ResponseFragment: fragmentAround(c.body, id),
			Observation:      fmt.Sprintf("who=%s what=%s owner=%s expected=denied actual=%s proof_matches_owner_baseline=%v", c.context.ID, id, owner.ID, nethttp.StatusText(status), c.matchesOwner),
			Reason:           "an additional cross-authorization-context attempt against the same resource, evaluated the same way as the primary one above",
		}))
	}
	return evidence
}

// probeAs issues one GET request against t (t.Parameter kept at its
// already-discovered value -- this detector never substitutes a
// DIFFERENT resource identifier, only a different CALLER identity)
// with as's Headers attached, through x (the only sanctioned request
// path).
func probeAs(ctx context.Context, x *detection.Executor, t detection.Target, as AuthContext) ([]byte, *nethttp.Response, error) {
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, t.URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build probe request: %w", err)
	}
	for k, v := range as.Headers {
		req.Header.Set(k, v)
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

// requestURL returns t's URL with t.Parameter's value replaced by id --
// used only for the evidence Request line (probeAs itself reuses t.URL
// verbatim, since this detector never changes the resource identifier).
func requestURL(t detection.Target, id string) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return t.URL
	}
	q := u.Query()
	q.Set(t.Parameter, id)
	u.RawQuery = q.Encode()
	return u.String()
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
// bounded evidence, never the full response.
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
