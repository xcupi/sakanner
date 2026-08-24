package traversal

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// --- shared test helpers (mirrors idor/sqli/xssreflected/ssrf) -----------

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

// testFS mirrors the lab's own travSynthFS -- a small, synthetic,
// in-memory "filesystem" keyed by clean relative paths. Never the real
// filesystem.
var testFS = map[string]string{
	"public/index.html":           "PUBLIC_FILE_MARKER",
	"protected/secret-marker.txt": "PATH_TRAVERSAL_SECRET_MARKER",
}

func travCase() TraversalCase {
	return TraversalCase{RelativePath: "../protected/secret-marker.txt", Marker: "PATH_TRAVERSAL_SECRET_MARKER"}
}

// vulnerableHandler mirrors the lab's /files/download/vulnerable
// exactly: naive path.Clean(path.Join("public", file)) with no
// containment check.
func vulnerableHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		resolved := path.Clean(path.Join("public", file))
		w.Header().Set("Content-Type", "text/plain")
		content, ok := testFS[resolved]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	}
}

// safeHandler mirrors the lab's /files/download/safe: resolves and
// cleans the same way, but verifies containment before use.
func safeHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		resolved := path.Clean(path.Join("public", file))
		w.Header().Set("Content-Type", "text/plain")
		if resolved != "public" && !strings.HasPrefix(resolved, "public/") {
			w.WriteHeader(403)
			w.Write([]byte("forbidden"))
			return
		}
		content, ok := testFS[resolved]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	}
}

// reflectHandler mirrors the lab's /files/download/reflect: echoes the
// requested value, never reads any file content at all.
func reflectHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Requested file: %s", file)
	}
}

// genericHandler mirrors the lab's /files/download/generic: a fixed
// response regardless of input.
func genericHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}
}

// --- Metadata / registration / candidate selection -----------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New([]TraversalCase{travCase()}).Metadata()
	if meta.ID != "path-traversal" {
		t.Errorf("ID = %q, want path-traversal", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityHigh {
		t.Errorf("DefaultSeverity = %q, want high", meta.DefaultSeverity)
	}
	if len(meta.Prerequisites) == 0 {
		t.Error("Prerequisites should document the TraversalCase requirement")
	}
}

func TestDetector_RegistersInRegistry(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New([]TraversalCase{travCase()})); err != nil {
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
	if err := r.Register(New([]TraversalCase{travCase()})); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(New([]TraversalCase{travCase()})); err == nil {
		t.Error("second Register with the same ID: want error, got nil")
	}
}

func TestEligible_PathLikeParameterNames(t *testing.T) {
	d := New([]TraversalCase{travCase()})
	names := []string{
		"file", "filename", "filepath", "path", "file_path", "document",
		"document_path", "template", "resource", "download", "attachment",
		"image", "directory", "FILE", "File_Path",
	}
	for _, name := range names {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: name, ParameterLocation: "query"}
		if !d.Eligible(tgt) {
			t.Errorf("Eligible(%q) = false, want true", name)
		}
	}
}

func TestEligible_RejectsNonPathLikeParameterName(t *testing.T) {
	d := New([]TraversalCase{travCase()})
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "color", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible(\"color\") = true, want false")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New([]TraversalCase{travCase()})
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "file", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for an http_service-kind target")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New([]TraversalCase{travCase()})
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "file", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a POST endpoint")
	}
}

// --- Detect: end-to-end scenarios -----------------------------------------

func TestDetect_VulnerableTraversal_HighConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "path_traversal" {
		t.Errorf("VulnerabilityType = %q, want path_traversal", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.8 {
		t.Errorf("Confidence = %v, want >= 0.8 (marker confirmed)", f.Confidence)
	}
	if f.AffectedParameter != "file" {
		t.Errorf("AffectedParameter = %q, want file", f.AffectedParameter)
	}
	// 3 items as of Phase 3.11: the legitimate-access baseline, the
	// not-found baseline, and the primary confirming probe -- see
	// docs/phase-3-11-scan-orchestrator.md "Real evidence integration".
	if len(f.Evidence) != 3 || f.Evidence[0].Content == "" || f.Evidence[1].Content == "" || f.Evidence[2].Content == "" {
		t.Errorf("Evidence = %+v, want 3 non-empty items (2 baselines + probe)", f.Evidence)
	}
}

func TestDetect_SecureCanonicalization_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- every traversal variant is correctly denied (403)", result.Outcome)
	}
}

func TestDetect_NoConfiguredCases_Skipped(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New(nil)
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped -- no operator-configured TraversalCase means nothing to test for", result.Outcome)
	}
}

func TestDetect_ReflectionOnly_NoFinding(t *testing.T) {
	// The classic reflected-parameter false-positive class (Phase 3.3's
	// lesson): the response ALWAYS echoes whatever value was requested,
	// including the not-found baseline's own random value -- without
	// stripPayload, comparing raw bodies would see two DIFFERENT echoed
	// strings and wrongly conclude "distinguishable from baseline."
	srv := httptest.NewServer(reflectHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- reflecting the input string is not evidence a file was read", result.Outcome)
	}
}

func TestDetect_GenericResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(genericHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a constant response never reflects a specific resource", result.Outcome)
	}
}

func TestDetect_ByIDLookup_NoFinding(t *testing.T) {
	// Parameterized/safely-resolved access (section 11.3): the "file"
	// value is only ever used as an opaque allowlist key, never
	// concatenated into a path -- a traversal-shaped value is simply
	// not a valid key.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		byID := map[string]string{"1": "PUBLIC_FILE_MARKER"}
		id := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		content, ok := byID[id]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestDetect_InvalidOriginalValue_404Skipped(t *testing.T) {
	// The originally-discovered value itself 404s against this endpoint
	// -- nothing to use as a "legitimate access" reference.
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "does-not-exist.txt")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the legitimate-access baseline itself 404s, nothing to compare against", result.Outcome)
	}
}

func TestDetect_AllowedButMarkerAbsent_MediumConfidenceFinding(t *testing.T) {
	// Allowed (2xx, non-empty), genuinely differs from the not-found
	// baseline even after stripping the reflected value, but the
	// specific configured marker never appears.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		if file == "index.html" {
			w.Write([]byte("PUBLIC_FILE_MARKER"))
			return
		}
		if strings.Contains(file, "protected") {
			w.Write([]byte("SOME_OTHER_FILE_CONTENT_NOT_THE_CONFIGURED_MARKER"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
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

// --- Errors: 403/404/timeout/cancellation/scope ---------------------------

func TestDetect_403Handling_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a 403 must not be interpreted as traversal", result.Outcome)
	}
}

func TestDetect_404Handling_NoFinding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	// A case whose RelativePath doesn't exist in this fixture's own
	// synthetic filesystem at all -- every variant 404s.
	d := New([]TraversalCase{{RelativePath: "../protected/does-not-exist.txt", Marker: "NEVER_APPEARS"}})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a 404 must not be interpreted as traversal", result.Outcome)
	}
}

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "file", "index.html")
	srv.Close()

	d := New([]TraversalCase{travCase()})
	x := newExecutor(true, detection.ExecutorConfig{})
	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a closed connection: want error, got nil")
	}
}

func TestDetect_Timeout_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("PUBLIC_FILE_MARKER"))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 20 * time.Millisecond})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a slow server with a short Executor timeout: want error, got nil")
	}
}

func TestDetect_ContextCancellation_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("PUBLIC_FILE_MARKER"))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
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
		w.Write([]byte("PUBLIC_FILE_MARKER"))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
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

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
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

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")

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

// --- Performance / response-size limits -----------------------------------

func TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests(t *testing.T) {
	const candidates = 10
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "file", "index.html")
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

	// 2 reference requests (legitimate-access + not-found) + exactly 1
	// variant request per candidate (the raw representation, first in
	// traversalVariants' order, confirms immediately against this
	// fixture, so the loop breaks before trying the remaining 3) = 3
	// requests per candidate, no more.
	if got, want := x.RequestCount(), int64(candidates*3); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 3 requests each)", got, want, candidates)
	}
}

func TestDetect_OversizedResponse_TruncatedNotUnbounded(t *testing.T) {
	// A response body far larger than maxBodySample must never be read
	// unbounded into memory -- io.LimitReader in probe/probeRaw enforces
	// this regardless of what the server sends.
	huge := strings.Repeat("A", maxBodySample*4)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(huge))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// Every response is identical oversized "A" filler regardless of
	// value requested -- the marker never appears, and after stripping
	// the reflected values (there are none here) the bodies are
	// identical, so this must resolve to NoFinding, not a crash or an
	// unbounded read.
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestDetect_EmptyResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Deliberately writes nothing.
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// The legitimate-access baseline itself is empty -- looksAllowed
	// requires a non-empty body, so there's no reference to compare
	// against at all.
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}
