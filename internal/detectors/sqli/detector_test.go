package sqli

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// fakeValidator mirrors the same minimal test-scope-validator pattern
// already used throughout this codebase (internal/ports, internal/http,
// internal/detection, internal/detectors/xssreflected) -- a local copy,
// since none of these packages export test helpers to each other.
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

// --- Metadata / registration / candidate selection -------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New().Metadata()
	if meta.ID != "sqli" {
		t.Errorf("ID = %q, want sqli", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityCritical {
		t.Errorf("DefaultSeverity = %q, want critical", meta.DefaultSeverity)
	}
	if len(meta.SupportedTargetTypes) != 1 || meta.SupportedTargetTypes[0] != detection.TargetKindEndpoint {
		t.Errorf("SupportedTargetTypes = %+v, want [endpoint]", meta.SupportedTargetTypes)
	}
	if len(meta.SupportedMethods) != 1 || meta.SupportedMethods[0] != nethttp.MethodGet {
		t.Errorf("SupportedMethods = %+v, want [GET]", meta.SupportedMethods)
	}
}

func TestDetector_RegistersInRegistry(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d, ok := r.Get("sqli")
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != "sqli" {
		t.Errorf("ID = %q, want sqli", d.Metadata().ID)
	}
}

func TestDetector_DuplicateRegistrationRejected(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New()); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(New()); err == nil {
		t.Error("second Register with the same ID: want error, got nil")
	}
}

func TestEligible_QueryParameterGETEndpoint(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "query"}
	if !d.Eligible(tgt) {
		t.Error("Eligible = false, want true for a GET query-parameter endpoint target")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for an http_service-kind target")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "id", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a POST endpoint (out of scope for this phase)")
	}
}

func TestEligible_RejectsEmptyParameter(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "", ParameterLocation: ""}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false when the target names no specific parameter")
	}
}

func TestEligible_RejectsNonQueryParameterLocation(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "header"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a non-query parameter location")
	}
}

// --- Detect: end-to-end scenarios against synthetic servers ------------

// sqliHandler models a tiny synthetic database-backed endpoint: rows is
// the "table," and the handler applies the exact string-concatenation
// semantics the id parameter should trigger if vulnerable == true.
func sqliHandler(vulnerable bool, errorOnMalformed bool) nethttp.HandlerFunc {
	rows := map[string]string{"1": "alice", "2": "bob"}
	names := []string{"alice", "bob", "admin"}
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("id")
		if !vulnerable {
			if name, ok := rows[id]; ok {
				w.Write([]byte("results: " + name))
				return
			}
			w.Write([]byte("results: (none)"))
			return
		}
		if id == "1' OR '1'='1" {
			body := "results: "
			for i, n := range names {
				if i > 0 {
					body += ", "
				}
				body += n
			}
			w.Write([]byte(body))
			return
		}
		if id == "'" || id == "1' AND '1'='2" {
			if errorOnMalformed {
				w.WriteHeader(nethttp.StatusInternalServerError)
				w.Write([]byte("You have an error in your SQL syntax near '" + id + "'"))
				return
			}
			w.Write([]byte("results: (none)"))
			return
		}
		if name, ok := rows[id]; ok {
			w.Write([]byte("results: " + name))
			return
		}
		w.Write([]byte("results: (none)"))
	}
}

func TestDetect_ErrorAndBooleanBothPresent_HighestConfidence(t *testing.T) {
	srv := httptest.NewServer(sqliHandler(true, true))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "sql_injection" {
		t.Errorf("VulnerabilityType = %q, want sql_injection", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9 (error + boolean both present)", f.Confidence)
	}
	if f.AffectedParameter != "id" {
		t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
	}
	// 2 items as of Phase 3.11: the baseline control probe plus the
	// combined error/boolean probe summary -- see
	// docs/phase-3-11-scan-orchestrator.md "Real evidence integration".
	if len(f.Evidence) != 2 || f.Evidence[0].Content == "" || f.Evidence[1].Content == "" {
		t.Errorf("Evidence = %+v, want 2 non-empty items (baseline + probe)", f.Evidence)
	}
	if x.RequestCount() != 4 {
		t.Errorf("RequestCount() = %d, want 4 (baseline + error + true + false)", x.RequestCount())
	}
}

func TestDetect_BooleanOnlyNoError_HighConfidenceCritical(t *testing.T) {
	srv := httptest.NewServer(sqliHandler(true, false)) // vulnerable, but never errors
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.7 || f.Confidence >= 0.9 {
		t.Errorf("Confidence = %v, want in [0.7, 0.9)", f.Confidence)
	}
}

func TestDetect_SafeParameterizedEndpoint_NoFinding(t *testing.T) {
	srv := httptest.NewServer(sqliHandler(false, false))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding (safe parameterized query must not be flagged)", result.Outcome)
	}
}

func TestDetect_GenericErrorEverywhere_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusInternalServerError)
		w.Write([]byte("Database error: something went wrong processing your request."))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the SAME generic error occurs for baseline too, so it is not evidence", result.Outcome)
	}
}

func TestDetect_DynamicContentUnrelatedToParameter_NoFinding(t *testing.T) {
	var counter int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		counter++
		w.Write([]byte("results: (none)\n<!-- request-id: " + strconv.Itoa(counter) + " -->"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the only variance is a dynamic counter unrelated to the parameter", result.Outcome)
	}
}

// TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding is the
// end-to-end regression test for a real false positive
// TestPhase3_3_SQLiDetector_MatchesGroundTruth (lab) found against
// the real Phase 3 lab's reflected-XSS and open-redirect fixtures: an
// endpoint that echoes its parameter verbatim (with no database
// involved at all) must not be flagged just because the true/false
// probe payloads are different strings from each other.
func TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("page not found: " + r.URL.Query().Get("id")))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the endpoint just echoes its parameter, with no SQL/database behavior involved", result.Outcome)
	}
}

func TestDetect_NonAnalyzableContentType_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\r\n\x1a\nfakepngbytes"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped (binary content is NOT_APPLICABLE)", result.Outcome)
	}
	if x.RequestCount() != 1 {
		t.Errorf("RequestCount() = %d, want 1 -- only the baseline probe should run before the content-type gate stops further probing", x.RequestCount())
	}
}

// --- Errors: connection failure, timeout, cancellation, scope ----------

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "id")
	srv.Close()

	d := New()
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

	d := New()
	tgt := targetFor(t, srv, "id")
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

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect with a cancelled context: want error, got nil")
	}
}

func TestDetect_CancellationDuringBaseline(t *testing.T) {
	var reached atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		reached.Add(1)
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect cancelled during baseline: want error, got nil")
	}
	// The in-flight baseline request's handler goroutine may still be
	// asleep server-side when Detect returns (the client gave up on the
	// response, but the handler itself isn't interrupted) -- wait for it
	// to actually finish before reading the counter, rather than racing
	// on it.
	time.Sleep(150 * time.Millisecond)
	if got := reached.Load(); got > 1 {
		t.Errorf("server was reached %d times, want at most 1 -- cancellation during baseline must stop before any further probes", got)
	}
}

func TestDetect_OutOfScope_ReturnsErrorWithoutDialing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(false, detection.ExecutorConfig{})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a denied target: want error, got nil")
	}
	if hits != 0 {
		t.Errorf("server received %d requests, want 0 -- scope denial must prevent the dial entirely", hits)
	}
}

// --- Deduplication (reusing the Phase 3.1 framework) --------------------

func TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate(t *testing.T) {
	srv := httptest.NewServer(sqliHandler(true, true))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")

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
	f1.DetectorID, f2.DetectorID = "sqli", "sqli"
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

// --- Performance: many concurrent candidates, one shared Executor ------

func TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests(t *testing.T) {
	const candidates = 15
	srv := httptest.NewServer(sqliHandler(true, true))
	defer srv.Close()

	d := New()
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "id")
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

	// 4 requests per candidate (baseline + error + true + false) --
	// exactly candidates*4, no more, regardless of concurrency.
	if got, want := x.RequestCount(), int64(candidates*4); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 4 probes each)", got, want, candidates)
	}
}
