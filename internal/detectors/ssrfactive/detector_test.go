package ssrfactive

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// testInternalResourceMarker stands in for whatever distinctive
// content a real internal-resource fixture serves (in the lab, this
// reuses ssrf-internal.scanner.test's own existing response text --
// see docs/phase-3-25-ssrf-active-detection.md section 3) -- the
// marker is caller-supplied to New, never a package constant, so
// these unit tests supply their own.
const testInternalResourceMarker = "TEST_INTERNAL_RESOURCE_MARKER"

// --- shared test helpers (mirrors internal/detectors/ssrf/sqliactive) ---

type fakeValidator struct{ allowed bool }

func (f *fakeValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) check() (scope.Decision, error) {
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

func newExecutor(allowed bool, cfg detection.ExecutorConfig) *detection.Executor {
	return detection.NewExecutor(&fakeValidator{allowed: allowed}, dns.NewFakeResolver(), cfg)
}

func targetFor(t *testing.T, srv *httptest.Server, param, location, method string) detection.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("could not parse listener IP %q", host)
	}
	return detection.Target{
		Kind: detection.TargetKindEndpoint, Host: host, IP: ip, Port: port, Scheme: "http",
		URL: srv.URL + "/", Path: "/", Method: method,
		Parameter: param, ParameterLocation: location,
	}
}

// fakeCallback mirrors internal/detectors/ssrf's own test double
// exactly (detector_test.go:72-110) -- a fully-controllable, in-memory
// CallbackClient for logic-level tests, duplicated here since these
// packages share no test helpers, matching this codebase's own
// established convention.
type fakeCallback struct {
	mu     sync.Mutex
	obs    map[string][]ssrf.Observation
	tokenN int
}

func newFakeCallback() *fakeCallback { return &fakeCallback{obs: map[string][]ssrf.Observation{}} }

func (f *fakeCallback) NewToken(ctx context.Context) (string, string, error) {
	f.mu.Lock()
	f.tokenN++
	token := fmt.Sprintf("token-%d", f.tokenN)
	f.mu.Unlock()
	return token, "http://callback.test/cb/" + token, nil
}

func (f *fakeCallback) Observations(ctx context.Context, token string) ([]ssrf.Observation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ssrf.Observation(nil), f.obs[token]...), nil
}

func (f *fakeCallback) inject(token string, o ssrf.Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.obs[token] = append(f.obs[token], o)
}

// --- Metadata / eligibility ------------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New(nil, "", "").Metadata()
	if meta.ID != "ssrf-active" {
		t.Errorf("ID = %q, want ssrf-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "url", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New(nil, "", "").Eligible(tgt) {
		t.Error("expected eligible for a GET, URL-shaped query parameter")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "url", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New(nil, "", "").Eligible(tgt) {
		t.Error("a POST query-location target should not be eligible")
	}
}

func TestEligible_FormBodyPathAnyMethod_True(t *testing.T) {
	for _, loc := range []string{"form", "body", "path"} {
		for _, method := range []string{nethttp.MethodGet, nethttp.MethodPost, nethttp.MethodPut} {
			tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "url", ParameterLocation: loc, Method: method}
			if !New(nil, "", "").Eligible(tgt) {
				t.Errorf("expected eligible for a %s %s-location target", method, loc)
			}
		}
	}
}

func TestEligible_NonURLName_False(t *testing.T) {
	for _, name := range []string{"page", "id", "sort", "note_id"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: name, ParameterLocation: "query", Method: nethttp.MethodGet}
		if New(nil, "", "").Eligible(tgt) {
			t.Errorf("%q should not be eligible (not URL-shaped)", name)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil, "", "").Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "url", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil, "", "").Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

// --- Detect: nil callback ----------------------------------------------

func TestDetect_NilCallback_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "should never be reached")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New(nil, "", "").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Fatalf("Outcome = %s, want skipped (nil callback)", result.Outcome)
	}
}

// --- Detect: Mode B (blind/OOB callback) --------------------------------

func vulnerableSSRFHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	target := r.URL.Query().Get("url")
	req, err := nethttp.NewRequest(nethttp.MethodGet, target, nil)
	if err != nil {
		w.WriteHeader(nethttp.StatusBadRequest)
		fmt.Fprint(w, "bad url")
		return
	}
	client := &nethttp.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(nethttp.StatusBadGateway)
		fmt.Fprintf(w, "fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	fmt.Fprintf(w, "fetched %s: %s", target, body)
}

func TestDetect_CallbackObserved_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// This handler never actually dials anything (the fake callback
		// URL is not a real, dialable host) -- it just needs to be
		// analyzable/successful for the baseline probe, and the test
		// injects the Mode-B observation directly (mirroring
		// internal/detectors/ssrf's own logic-level test style).
		fmt.Fprint(w, "some response content, plenty of bytes to be non-trivial")
	}))
	defer srv.Close()

	cb := newFakeCallback()
	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	d := New(cb, "", "")

	// fakeCallback's tokens are deterministic ("token-1", "token-2",
	// ...); this cb instance is fresh, Mode A is skipped (empty
	// internalResourceURL), so Mode B's NewToken call -- the only one
	// Detect will ever make here -- is guaranteed to return "token-1".
	// Pre-injecting before Detect even runs avoids any goroutine/race
	// entirely: map writes under fakeCallback's own mutex are safe
	// regardless of whether NewToken has "created" the key yet (a Go
	// map read of a not-yet-written key is simply its zero value).
	cb.inject("token-1", ssrf.Observation{Method: "GET", Path: "/cb/token-1", RemoteAddr: "127.0.0.1:1234", Timestamp: time.Now()})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (callback observed)", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "ssrf" {
		t.Errorf("VulnerabilityType = %q, want ssrf", f.VulnerabilityType)
	}
	if f.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9 (callback-confirmed, Mode A not attempted)", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + mode-B), got %d", len(f.Evidence))
	}
}

func TestDetect_NoCallbackNoMarker_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "an ordinary response, never fetches anything, never embeds any marker")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New(newFakeCallback(), "", "").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (no callback observed, no marker configured)", result.Outcome)
	}
}

// --- Detect: Mode A (response-based, internal resource marker) ---------

func TestDetect_InternalResourceMarkerEmbedded_Finding(t *testing.T) {
	resourceSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, testInternalResourceMarker)
	}))
	defer resourceSrv.Close()

	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableSSRFHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	d := New(newFakeCallback(), resourceSrv.URL+"/resource", testInternalResourceMarker)

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (internal resource marker embedded)", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want 0.85 (marker-confirmed only, no callback)", f.Confidence)
	}
	if len(f.Evidence) != 3 {
		t.Errorf("expected 3 evidence items (baseline + mode-A + mode-B), got %d", len(f.Evidence))
	}
}

func TestDetect_ReflectedURLOnly_NoMarker_NoFinding(t *testing.T) {
	// The application reflects the URL verbatim but never fetches it --
	// the marker is never present, and no callback fires.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		fmt.Fprintf(w, "<html><body>you provided: %s</body></html>", target)
	}))
	defer srv.Close()

	resourceSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, testInternalResourceMarker)
	}))
	defer resourceSrv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	d := New(newFakeCallback(), resourceSrv.URL+"/resource", testInternalResourceMarker)

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (URL reflected, never fetched -- marker never embedded)", result.Outcome)
	}
}

// --- Scope enforcement ---------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(false, detection.ExecutorConfig{})
	result, err := New(newFakeCallback(), "", "").Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for a denied-scope target")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a scope-denied target must never produce a finding")
	}
	if hits != 0 {
		t.Fatalf("SECURITY: server received %d requests despite a denied scope, want 0", hits)
	}
}

// --- Cancellation ----------------------------------------------------------

// TestDetect_ContextCancelledDuringCallbackWait_ReturnsPromptly proves
// docs/phase-3-25-ssrf-active-detection.md section 14's own
// requirement: cancellation during the bounded callback poll returns
// immediately via the ctx.Done() select branch, never waiting out the
// full callbackMaxWait. The context is cancelled well AFTER the
// baseline/mode-B probe requests would have completed (the httptest
// server responds near-instantly) but well BEFORE callbackMaxWait
// (200ms) would otherwise elapse -- isolating the cancellation to the
// POLLING phase specifically, not an earlier stage.
func TestDetect_ContextCancelledDuringCallbackWait_ReturnsPromptly(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "an ordinary response, plenty of content to be non-trivial")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := New(newFakeCallback(), "", "").Detect(ctx, tgt, x)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected a context-cancellation error")
	}
	if elapsed >= callbackMaxWait {
		t.Errorf("Detect took %v after context cancellation, want well under callbackMaxWait=%v (the poll must stop at ctx.Done(), not run out the full wait)", elapsed, callbackMaxWait)
	}
}
