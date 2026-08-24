package cmdinjection

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// --- shared test helpers (mirrors traversal/idor/sqli/xssreflected/ssrf) ---

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

func targetFor(t *testing.T, srv *httptest.Server, param, value string) detection.Target {
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
		URL: srv.URL + "/?" + param + "=" + value, Path: "/", Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "query",
	}
}

// testPattern mirrors the lab's own cmdInjectionPattern exactly --
// pure Go regexp matching, never a real shell.
var testPattern = regexp.MustCompile(`(?:;|\||&&)\s*` + labCommand + `\s+(\S+)`)

// vulnerableHandler mirrors the lab's /api/ping/vulnerable exactly.
func vulnerableHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if m := testPattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", host)
	}
}

// safeHandler mirrors the lab's /api/ping/safe: strict allowlist.
var safeHostPattern = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

func safeHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if !safeHostPattern.MatchString(host) {
			w.WriteHeader(400)
			w.Write([]byte("invalid host: rejected"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", host)
	}
}

// reflectHandler mirrors the lab's /api/ping/reflect: echoes the
// requested value, never attempts grammar matching.
func reflectHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Requested host: %s", host)
	}
}

// genericHandler mirrors the lab's /api/ping/generic: a fixed response
// regardless of input.
func genericHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}
}

// staticMarkerHandler mirrors the lab's /api/ping/static-marker:
// always includes the literal marker substring, never with a real
// per-probe token.
func staticMarkerHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "PING %s: normal response\n<!-- see COMMAND_INJECTION_MARKER docs -->", host)
	}
}

// --- Metadata / registration / candidate selection -----------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New().Metadata()
	if meta.ID != ID {
		t.Errorf("ID = %q, want %s", meta.ID, ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityHigh {
		t.Errorf("DefaultSeverity = %q, want high", meta.DefaultSeverity)
	}
}

func TestDetector_RegistersInRegistry(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d, ok := r.Get(ID)
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != ID {
		t.Errorf("ID = %q, want %s", d.Metadata().ID, ID)
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

func TestEligible_CommandLikeParameterNames(t *testing.T) {
	d := New()
	names := []string{
		"host", "hostname", "ip", "address", "domain", "command", "cmd",
		"exec", "executable", "program", "file", "path", "target", "query",
		"HOST", "Command",
	}
	for _, name := range names {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: name, ParameterLocation: "query"}
		if !d.Eligible(tgt) {
			t.Errorf("Eligible(%q) = false, want true", name)
		}
	}
}

func TestEligible_RejectsNonCommandLikeParameterName(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "color", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible(\"color\") = true, want false")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "host", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for an http_service-kind target")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New()
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "host", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a POST endpoint")
	}
}

// --- Detect: end-to-end scenarios -----------------------------------------

func TestDetect_VulnerableCommandInjection_HighConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "command_injection" {
		t.Errorf("VulnerabilityType = %q, want command_injection", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9 (exact correlation token confirmed)", f.Confidence)
	}
	if f.AffectedParameter != "host" {
		t.Errorf("AffectedParameter = %q, want host", f.AffectedParameter)
	}
	// 2 items as of Phase 3.11: the legitimate-access baseline this
	// detector already fetches as an eligibility gate, plus the
	// confirmed probe -- see docs/phase-3-11-scan-orchestrator.md "Real
	// evidence integration."
	if len(f.Evidence) != 2 || f.Evidence[0].Content == "" || f.Evidence[1].Content == "" {
		t.Errorf("Evidence = %+v, want 2 non-empty items (baseline + probe)", f.Evidence)
	}
}

func TestDetect_SafeAllowlist_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- every injection representation is rejected (400)", result.Outcome)
	}
}

func TestDetect_ReflectionOnly_NoFinding(t *testing.T) {
	srv := httptest.NewServer(reflectHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- reflecting the injected text is not command execution", result.Outcome)
	}
}

func TestDetect_GenericResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(genericHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a constant response never proves execution", result.Outcome)
	}
}

func TestDetect_StaticMarkerWithoutToken_NoFinding(t *testing.T) {
	// The bare substring "COMMAND_INJECTION_MARKER" appears in EVERY
	// response from this fixture, regardless of input -- but never
	// followed by ":" and this probe's own exact token. A naive
	// substring-only check would false-positive here; the exact
	// prefix+token requirement must not.
	srv := httptest.NewServer(staticMarkerHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the bare marker substring without a matching token is not proof", result.Outcome)
	}
}

func TestDetect_ByIDLookup_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		byID := map[string]string{"1": "127.0.0.1"}
		id := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		target, ok := byID[id]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("unknown host id"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal response", target)
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestDetect_InvalidOriginalValue_400Skipped(t *testing.T) {
	// The legitimate-access reference itself is rejected -- nothing to
	// establish reachability from.
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "; not-allowed")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the legitimate-access baseline itself is rejected", result.Outcome)
	}
}

func TestDetect_ErrorResponseAlone_NoFinding(t *testing.T) {
	// Command-related ERROR TEXT alone (section 10) -- no marker, no
	// execution proof -- must never confirm a finding, even though it's
	// suggestive.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if host == "127.0.0.1" {
			w.Write([]byte("PING 127.0.0.1: normal response"))
			return
		}
		w.WriteHeader(500)
		w.Write([]byte("shell syntax error: command not found: invalid command, execution error"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- generic command-related error text alone is never sufficient proof", result.Outcome)
	}
}

// --- Errors: 400/timeout/cancellation/scope --------------------------------

func TestDetect_400Handling_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a 400 must not be interpreted as execution", result.Outcome)
	}
}

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "host", "127.0.0.1")
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
		w.Write([]byte("PING 127.0.0.1: normal response"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 20 * time.Millisecond})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a slow server with a short Executor timeout: want error, got nil")
	}
}

func TestDetect_ContextCancellation_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("PING 127.0.0.1: normal response"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
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
		w.Write([]byte("PING 127.0.0.1: normal response"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect cancelled during baseline: want error, got nil")
	}
	time.Sleep(150 * time.Millisecond)
	if got := reached.Load(); got > 1 {
		t.Errorf("server was reached %d times, want at most 1 -- cancellation during the legitimate-access baseline must stop before any further probe", got)
	}
}

func TestDetect_OutOfScope_ReturnsErrorWithoutDialing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(false, detection.ExecutorConfig{})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a denied target: want error, got nil")
	}
	if hits != 0 {
		t.Errorf("server received %d requests, want 0 -- scope denial must prevent the dial entirely", hits)
	}
}

// --- Deduplication -----------------------------------------------------

func TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")

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
	f1.DetectorID, f2.DetectorID = ID, ID
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

// --- Performance / response limits -----------------------------------

func TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests(t *testing.T) {
	const candidates = 10
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New()
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "host", "127.0.0.1")
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

	// 1 legitimate-access reference + exactly 1 variant request per
	// candidate (the semicolon variant, first in commandVariants'
	// order, confirms immediately against this fixture) = 2 requests
	// per candidate, no more.
	if got, want := x.RequestCount(), int64(candidates*2); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 2 requests each)", got, want, candidates)
	}
}

func TestDetect_OversizedResponse_TruncatedNotUnbounded(t *testing.T) {
	huge := make([]byte, maxBodySample*4)
	for i := range huge {
		huge[i] = 'A'
	}
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(huge)
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestDetect_EmptyResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}
