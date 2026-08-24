// Package ssrf implements sakanner's third real vulnerability
// detector: server-side request forgery, detected via an out-of-band
// callback correlation -- the target application is given a controlled
// callback URL and the detector checks whether a callback service
// (never a real external destination) observed a server-side request
// for it. It implements detection.Detector (internal/detection, Phase
// 3.1) unchanged -- see docs/phase-3-4-ssrf.md for the full design
// writeup and "How to implement a new detector" in
// docs/phase-3-1-detection-engine.md for the contract this follows.
//
// This package performs DETECTION only. It never enumerates internal
// networks, never probes cloud metadata endpoints, never scans ports,
// and never attempts to extract data through a confirmed SSRF -- the
// only "payload" this detector ever sends is a single callback URL
// pointing at its own configured CallbackClient, never anything an
// operator or caller supplies. See docs/phase-3-4-ssrf.md "What this
// detector does not do."
package ssrf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "ssrf"

// baselineValue is a plain, non-URL-shaped control value -- what a
// normal request looks like. It is deliberately NOT a URL at all (not
// even a lab-internal one) so that even a genuinely vulnerable target
// application's own input validation harmlessly rejects it without
// ever attempting a dial -- the baseline's only job is establishing
// reference response characteristics, never testing fetch behavior
// itself.
const baselineValue = "sakannerSSRFBASELINE"

// maxBodySample bounds how much of a response body this detector reads
// into memory per probe -- matches every other detector's bound.
const maxBodySample = 256 * 1024

// evidenceFragmentRadius bounds how much surrounding context is kept
// around matched evidence text in stored findings.
const evidenceFragmentRadius = 80

// Callback polling. The lab's own fixtures perform their server-side
// fetch synchronously, inline within the same request/response cycle
// the probe triggers -- so in practice the very first poll already
// finds the observation. The bounded poll loop still exists (rather
// than a single check) to correctly model a target application whose
// SSRF manifests asynchronously (a queued job, a webhook processor),
// and to give TestDetect_DelayedCallback_StillCorrelates something
// real to exercise. Both bounds are small and fully deterministic --
// this is local, in-process test infrastructure, never a real network
// round trip to wait on.
const (
	callbackPollInterval = 10 * time.Millisecond
	callbackMaxWait      = 200 * time.Millisecond
)

// urlLikeParameterNames is the exact, task-specified name heuristic --
// see docs/phase-3-4-ssrf.md "Candidate selection" for why parameter
// NAME is the only signal available today (Phase 2's recon model has
// no parameter-value-shape classification yet, the same honestly-
// documented gap xssreflected and sqli both already carry).
var urlLikeParameterNames = map[string]bool{
	"url": true, "uri": true, "target": true, "destination": true,
	"redirect": true, "callback": true, "webhook": true, "endpoint": true,
	"image": true, "resource": true,
}

func isURLLikeParameterName(name string) bool {
	return urlLikeParameterNames[strings.ToLower(name)]
}

// Detector implements detection.Detector for SSRF.
type Detector struct {
	callback CallbackClient
}

// New returns a ready-to-register Detector that injects callback URLs
// obtained from cb and checks it for observations. cb is required for
// meaningful detection; see CallbackClient's doc comment for why no
// production implementation ships in this build yet -- a nil cb makes
// every Detect call return OutcomeSkipped rather than panicking, so a
// caller that constructs one anyway (e.g. while wiring is incomplete)
// fails safe.
func New(cb CallbackClient) *Detector {
	return &Detector{callback: cb}
}

// Metadata implements detection.Detector.
func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "SSRF Detector",
		Category:             "ssrf",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		Prerequisites:        []string{"out-of-band callback infrastructure (CallbackClient) must be configured -- not wired into production yet, see docs/phase-3-4-ssrf.md"},
		DefaultSeverity:      models.SeverityCritical,
	}
}

// Eligible implements detection.Detector: only a GET, query-parameter
// endpoint target whose parameter NAME looks URL-like is ever a
// candidate. See docs/phase-3-4-ssrf.md "Candidate selection."
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Method == nethttp.MethodGet &&
		t.Parameter != "" &&
		t.ParameterLocation == "query" &&
		isURLLikeParameterName(t.Parameter)
}

// Detect implements detection.Detector. See docs/phase-3-4-ssrf.md
// "Probe" and "Confidence" for the full rationale.
func (d Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if d.callback == nil {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	baseline, baseResp, err := probe(ctx, x, t, baselineValue)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrf: baseline probe: %w", err)
	}
	if !isAnalyzable(baseResp, baseline) {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	token, callbackURL, err := d.callback.NewToken(ctx)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrf: obtaining callback token: %w", err)
	}

	probeBody, probeResp, err := probe(ctx, x, t, callbackURL)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrf: callback probe: %w", err)
	}

	observations, err := d.waitForCallback(ctx, token)
	if err != nil {
		return detection.Result{}, fmt.Errorf("ssrf: waiting for callback: %w", err)
	}

	if len(observations) > 0 {
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
			d.finding(t, models.SeverityCritical, 0.9, baseline, baseResp, callbackURL, token, observations, probeBody, probeResp,
				"the callback service observed a server-side request for the unique, per-probe callback URL injected through this parameter -- direct, correlated confirmation of a server-side fetch"),
		}}, nil
	}

	// No callback observed -- fall back to a weaker, purely behavioral
	// signal: does the probe response differ from baseline in a way
	// consistent with an attempted (but unconfirmed) fetch. Both bodies
	// have the injected payload stripped first (see normalize.go) so an
	// endpoint that merely ECHOES the parameter back doesn't produce a
	// false difference for the trivial reason that baselineValue and
	// callbackURL are different strings.
	baseStripped := normalizeBody(stripPayload(baseline, baselineValue))
	probeStripped := normalizeBody(stripPayload(probeBody, callbackURL))
	if baseStripped == probeStripped {
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	if containsFetchErrorPhrase(probeBody) && !containsFetchErrorPhrase(baseline) {
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
			d.finding(t, models.SeverityHigh, 0.5, baseline, baseResp, callbackURL, token, nil, probeBody, probeResp,
				"the probe response (unlike baseline) contains wording consistent with an attempted outbound network fetch, but no callback was observed -- a strong indication without full confirmation"),
		}}, nil
	}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, models.SeverityMedium, 0.25, baseline, baseResp, callbackURL, token, nil, probeBody, probeResp,
			"the probe response differs from baseline after normalization, but neither a callback nor specific fetch-attempt wording was observed -- a weak, unconfirmed indication"),
	}}, nil
}

// waitForCallback polls d.callback.Observations for token, bounded by
// callbackMaxWait -- never a permanent goroutine, never unbounded
// polling, and ctx-aware so cancellation stops the wait immediately.
func (d Detector) waitForCallback(ctx context.Context, token string) ([]Observation, error) {
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

// finding builds a models.Finding. Only the fields a detector is
// expected to set are populated here -- DetectorID/Host/Port/URL/
// Method/AffectedEndpoint/ScanID/Source/timestamps are filled by the
// engine's normalizeFinding (Phase 3.1), which never overwrites what's
// already set here.
func (d Detector) finding(t detection.Target, severity models.Severity, confidence float64, baseline []byte, baseResp *nethttp.Response, callbackURL, token string, observations []Observation, body []byte, resp *nethttp.Response, reason string) models.Finding {
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	baselineStatus := 0
	if baseResp != nil {
		baselineStatus = baseResp.StatusCode
	}

	obsDesc := "none"
	if len(observations) > 0 {
		o := observations[0]
		obsDesc = fmt.Sprintf("%s %s from %s at %s", o.Method, o.Path, o.RemoteAddr, o.Timestamp.Format(time.RFC3339Nano))
	}

	return models.Finding{
		VulnerabilityType: "ssrf",
		Title:             "Server-Side Request Forgery (SSRF)",
		Description: fmt.Sprintf(
			"The %q parameter on %s appears to cause the application to perform a server-side request to an attacker-controlled destination. This may allow an attacker to reach internal services, cloud metadata endpoints, or other network resources not otherwise exposed.",
			t.Parameter, t.Path,
		),
		Severity:          severity,
		Confidence:        confidence,
		AffectedParameter: t.Parameter,
		Remediation:       "Validate and restrict server-side-fetched URLs against an allowlist of expected hosts/schemes; never fetch a raw, attacker-supplied URL. Where outbound requests are required, route them through a proxy that blocks loopback, link-local, and private (RFC1918) address ranges, and disable following redirects to unvalidated destinations.",
		Evidence: []models.Evidence{
			// The unmodified control request/response this detector
			// already fetches and consults for its stripped-body and
			// fetch-error-phrase differentials -- captured as its own
			// record instead of being entirely discarded (see
			// docs/phase-3-11-scan-orchestrator.md "Real evidence
			// integration").
			detection.NewTypedRequestResponseEvidence(models.EvidenceKindBaseline, "", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s", requestURL(t, baselineValue)),
				Response:         fmt.Sprintf("HTTP %d", baselineStatus),
				StatusCode:       baselineStatus,
				Parameter:        t.Parameter,
				Payload:          baselineValue,
				ResponseFragment: fragmentAround(baseline, baselineValue),
				Observation:      fmt.Sprintf("baseline_status=%d baseline_fetch_error_phrase=%v", baselineStatus, containsFetchErrorPhrase(baseline)),
				Reason:           "a plain, non-URL-shaped control value establishes reference response characteristics, so the callback probe below can be judged against it rather than in isolation",
			}),
			detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
				Request:          fmt.Sprintf("GET %s (callback_url=%q, token=%q)", requestURL(t, "{value}"), callbackURL, token),
				Response:         fmt.Sprintf("HTTP %d", status),
				StatusCode:       status,
				Parameter:        t.Parameter,
				Payload:          callbackURL,
				ResponseFragment: fragmentAround(body, callbackURL),
				Observation:      fmt.Sprintf("callback_token=%s callback_observed=%v detail=%q", token, len(observations) > 0, obsDesc),
				Reason:           reason,
			}),
		},
	}
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
		return t.URL
	}
	q := u.Query()
	q.Set(t.Parameter, payload)
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
