package ssrf

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// --- shared test helpers (mirrors internal/detectors/sqli, xssreflected) ---

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

func targetFor(t *testing.T, srv *httptest.Server, param string) detection.Target {
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
		URL: srv.URL + "/?" + param + "=placeholder", Path: "/", Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "query",
	}
}

// fakeCallback is a fully-controllable, in-memory CallbackClient --
// used for logic-level tests (correlation, isolation, timing, errors)
// where real HTTP round trips would only add noise. testCallbackServer
// (below) is used instead wherever a test specifically wants to prove
// the detector works against a REAL out-of-band HTTP recorder, not a
// mock.
type fakeCallback struct {
	mu          sync.Mutex
	obs         map[string][]Observation
	tokenN      int
	newTokenErr error
	obsErr      error
	afterNewTok func(token string) // hook, for injecting a delayed/async observation
}

func newFakeCallback() *fakeCallback { return &fakeCallback{obs: map[string][]Observation{}} }

func (f *fakeCallback) NewToken(ctx context.Context) (string, string, error) {
	if f.newTokenErr != nil {
		return "", "", f.newTokenErr
	}
	f.mu.Lock()
	f.tokenN++
	token := fmt.Sprintf("token-%d", f.tokenN)
	f.mu.Unlock()
	if f.afterNewTok != nil {
		f.afterNewTok(token)
	}
	return token, "http://callback.test/cb/" + token, nil
}

func (f *fakeCallback) Observations(ctx context.Context, token string) ([]Observation, error) {
	if f.obsErr != nil {
		return nil, f.obsErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Observation(nil), f.obs[token]...), nil
}

func (f *fakeCallback) inject(token string, o Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.obs[token] = append(f.obs[token], o)
}

// testCallbackServer is a real, local, non-forwarding HTTP recorder --
// a minimal standalone equivalent of lab.SSRFCallbackServer,
// scoped to this package's own tests to avoid lab importing this
// package while this package also imports lab (a cycle).
type testCallbackServer struct {
	srv *httptest.Server
	mu  sync.Mutex
	obs map[string][]Observation
}

func newTestCallbackServer(t *testing.T) *testCallbackServer {
	t.Helper()
	c := &testCallbackServer{obs: map[string][]Observation{}}
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/cb/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/cb/")
		c.mu.Lock()
		c.obs[token] = append(c.obs[token], Observation{Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr, Timestamp: time.Now().UTC()})
		c.mu.Unlock()
		w.WriteHeader(nethttp.StatusOK)
		w.Write([]byte("ok"))
	})
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *testCallbackServer) NewToken(ctx context.Context) (string, string, error) {
	c.mu.Lock()
	token := fmt.Sprintf("real-token-%d", len(c.obs)+1000)
	c.mu.Unlock()
	return token, c.srv.URL + "/cb/" + token, nil
}

func (c *testCallbackServer) Observations(ctx context.Context, token string) ([]Observation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Observation(nil), c.obs[token]...), nil
}

// --- Metadata / registration / candidate selection ---------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New(newFakeCallback()).Metadata()
	if meta.ID != "ssrf" {
		t.Errorf("ID = %q, want ssrf", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityCritical {
		t.Errorf("DefaultSeverity = %q, want critical", meta.DefaultSeverity)
	}
	if len(meta.Prerequisites) == 0 {
		t.Error("Prerequisites should document the callback-infrastructure requirement")
	}
}

func TestDetector_RegistersInRegistry(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New(newFakeCallback())); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d, ok := r.Get("ssrf")
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != "ssrf" {
		t.Errorf("ID = %q, want ssrf", d.Metadata().ID)
	}
}

func TestDetector_DuplicateRegistrationRejected(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New(newFakeCallback())); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(New(newFakeCallback())); err == nil {
		t.Error("second Register with the same ID: want error, got nil")
	}
}

func TestEligible_URLLikeParameterNames(t *testing.T) {
	d := New(newFakeCallback())
	for _, name := range []string{"url", "uri", "target", "destination", "redirect", "callback", "webhook", "endpoint", "image", "resource", "URL", "Target"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: name, ParameterLocation: "query"}
		if !d.Eligible(tgt) {
			t.Errorf("Eligible(%q) = false, want true", name)
		}
	}
}

func TestEligible_RejectsNonURLLikeParameterName(t *testing.T) {
	d := New(newFakeCallback())
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "username", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible(\"username\") = true, want false -- not URL-like")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New(newFakeCallback())
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "url", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for an http_service-kind target")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New(newFakeCallback())
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "url", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a POST endpoint")
	}
}

func TestEligible_RejectsEmptyParameter(t *testing.T) {
	d := New(newFakeCallback())
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "", ParameterLocation: ""}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false when the target names no specific parameter")
	}
}

// --- Detect: end-to-end against a real callback server ------------------

func TestDetect_CallbackObserved_HighConfidenceFinding(t *testing.T) {
	cb := newTestCallbackServer(t)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		if target == baselineValue || target == "" {
			w.Write([]byte("results: baseline"))
			return
		}
		// Genuinely vulnerable: fetches whatever URL it's given.
		resp, err := nethttp.Get(target)
		if err != nil {
			w.WriteHeader(nethttp.StatusBadGateway)
			fmt.Fprintf(w, "fetch failed: %v", err)
			return
		}
		defer resp.Body.Close()
		w.Write([]byte("fetched"))
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "ssrf" {
		t.Errorf("VulnerabilityType = %q, want ssrf", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.8 {
		t.Errorf("Confidence = %v, want >= 0.8 (callback observed)", f.Confidence)
	}
	if f.AffectedParameter != "url" {
		t.Errorf("AffectedParameter = %q, want url", f.AffectedParameter)
	}
	// 2 items as of Phase 3.11: the baseline control probe plus the
	// callback probe -- see docs/phase-3-11-scan-orchestrator.md "Real
	// evidence integration".
	if len(f.Evidence) != 2 || f.Evidence[0].Content == "" || f.Evidence[1].Content == "" {
		t.Errorf("Evidence = %+v, want 2 non-empty items (baseline + probe)", f.Evidence)
	}
}

func TestDetect_NoServerSideFetch_NoFinding(t *testing.T) {
	cb := newTestCallbackServer(t)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		w.Write([]byte("you provided: " + target)) // reflects, never fetches
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- reflection alone is not sufficient evidence", result.Outcome)
	}
}

func TestDetect_IdenticalResponseRegardlessOfInput_NoFinding(t *testing.T) {
	cb := newTestCallbackServer(t)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("saved")) // completely ignores the parameter
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestDetect_FetchErrorWordingWithoutCallback_MediumFinding(t *testing.T) {
	cb := newFakeCallback() // never observes anything
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		if target == baselineValue {
			w.Write([]byte("results: baseline"))
			return
		}
		w.WriteHeader(nethttp.StatusBadGateway)
		w.Write([]byte("fetch failed: connection refused"))
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence <= 0.3 || f.Confidence >= 0.8 {
		t.Errorf("Confidence = %v, want a medium value in (0.3, 0.8)", f.Confidence)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
}

func TestDetect_GenericDifferenceWithoutCallback_LowFinding(t *testing.T) {
	cb := newFakeCallback()
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		if target == baselineValue {
			w.Write([]byte("status: pending"))
			return
		}
		w.Write([]byte("status: processing")) // differs, but no fetch-error wording and no callback
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence >= 0.3 {
		t.Errorf("Confidence = %v, want a low value (< 0.3)", f.Confidence)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
}

func TestDetect_ReflectedCallbackURLDoesNotCauseFalsePositive(t *testing.T) {
	// The callback URL is echoed back verbatim -- without stripPayload,
	// this would show a "difference" from baseline for the trivial
	// reason that baselineValue and the callback URL are different
	// strings, exactly the false-positive class Phase 3.3 found for
	// sqli. Applied here from the start.
	cb := newFakeCallback()
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		w.Write([]byte("echo: " + target))
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- reflecting the callback URL is not evidence of a server-side fetch", result.Outcome)
	}
}

func TestDetect_NonAnalyzableContentType_Skipped(t *testing.T) {
	cb := newFakeCallback()
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\r\n\x1a\nfakepngbytes"))
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped", result.Outcome)
	}
}

func TestDetect_NilCallbackClient_Skipped(t *testing.T) {
	d := New(nil)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped for a nil CallbackClient", result.Outcome)
	}
}

// --- Errors: connection failure, timeout, cancellation, scope ----------

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "url")
	srv.Close()

	d := New(newFakeCallback())
	x := newExecutor(true, detection.ExecutorConfig{})
	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a closed connection: want error, got nil")
	}
}

func TestDetect_Timeout_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 20 * time.Millisecond})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a slow server with a short Executor timeout: want error, got nil")
	}
}

func TestDetect_ContextCancellation_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect with a cancelled context: want error, got nil")
	}
}

func TestDetect_CancellationWhileWaitingForCallback(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cb := newFakeCallback() // never observes anything -- forces the wait loop to run
	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := d.Detect(ctx, tgt, x)
		done <- err
	}()

	time.Sleep(15 * time.Millisecond) // let it reach the poll loop
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Detect cancelled while waiting for a callback: want error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Detect did not return within 2s of cancellation -- the callback wait loop is not respecting ctx")
	}
}

func TestDetect_OutOfScope_ReturnsErrorWithoutDialing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	x := newExecutor(false, detection.ExecutorConfig{})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a denied target: want error, got nil")
	}
	if hits != 0 {
		t.Errorf("server received %d requests, want 0 -- scope denial must prevent the dial entirely", hits)
	}
}

// --- Deduplication -------------------------------------------------------

func TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate(t *testing.T) {
	cb := newTestCallbackServer(t)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		if target == baselineValue {
			w.Write([]byte("results: baseline"))
			return
		}
		nethttp.Get(target) //nolint:errcheck
		w.Write([]byte("fetched"))
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")

	first, err := d.Detect(context.Background(), tgt, newExecutor(true, detection.ExecutorConfig{}))
	if err != nil {
		t.Fatalf("first Detect: %v", err)
	}
	second, err := d.Detect(context.Background(), tgt, newExecutor(true, detection.ExecutorConfig{}))
	if err != nil {
		t.Fatalf("second Detect: %v", err)
	}

	f1 := first.Findings[0]
	f2 := second.Findings[0]
	f1.ID, f2.ID = "run-1", "run-2"
	f1.DetectorID, f2.DetectorID = "ssrf", "ssrf"
	f1.Host, f2.Host = tgt.Host, tgt.Host
	f1.Port, f2.Port = tgt.Port, tgt.Port
	f1.AffectedEndpoint, f2.AffectedEndpoint = tgt.Path, tgt.Path
	f1.Method, f2.Method = tgt.Method, tgt.Method

	kept, duplicates := detection.Deduplicate(nil, []models.Finding{f1, f2})
	if len(kept) != 1 {
		t.Errorf("kept = %d findings, want 1", len(kept))
	}
	if duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", duplicates)
	}
}

// --- Performance -----------------------------------------------------------

func TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests(t *testing.T) {
	const candidates = 12
	cb := newTestCallbackServer(t)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		if target == baselineValue {
			w.Write([]byte("results: baseline"))
			return
		}
		nethttp.Get(target) //nolint:errcheck
		w.Write([]byte("fetched"))
	}))
	defer srv.Close()

	d := New(cb)
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "url")
		go func() {
			r, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				errs <- err
				return
			}
			results <- r
		}()
	}

	for i := 0; i < candidates; i++ {
		select {
		case err := <-errs:
			t.Fatalf("Detect: %v", err)
		case r := <-results:
			if r.Outcome != detection.OutcomeFinding {
				t.Errorf("candidate %d: Outcome = %v, want OutcomeFinding", i, r.Outcome)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Detect calls -- possible goroutine leak or deadlock")
		}
	}

	// 2 requests to the TARGET per candidate (baseline + callback probe)
	// -- polling the callback service is a direct, in-process method
	// call (see CallbackClient), never counted against the target's
	// Executor request budget.
	if got, want := x.RequestCount(), int64(candidates*2); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 2 target requests each)", got, want, candidates)
	}
}
