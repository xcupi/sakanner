package xssreflected

import (
	"context"
	"html"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// fakeValidator mirrors the same minimal test-scope-validator pattern
// already used throughout this codebase (internal/ports, internal/http,
// internal/detection's own tests) -- a local copy, since none of these
// packages export test helpers to each other.
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

// targetFor builds a TargetKindEndpoint Target pointing at srv, with
// the given parameter name and an arbitrary starting value (mirroring
// what BuildTargets would have produced from a crawled
// "?<param>=<anything>" URL).
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
	if meta.ID != "xss-reflected" {
		t.Errorf("ID = %q, want xss-reflected", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityHigh {
		t.Errorf("DefaultSeverity = %q, want high", meta.DefaultSeverity)
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
	d, ok := r.Get("xss-reflected")
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != "xss-reflected" {
		t.Errorf("ID = %q, want xss-reflected", d.Metadata().ID)
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
	t1 := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "q", ParameterLocation: "query"}
	if !d.Eligible(t1) {
		t.Error("Eligible = false, want true for a GET query-parameter endpoint target")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New()
	t1 := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "q", ParameterLocation: "query"}
	if d.Eligible(t1) {
		t.Error("Eligible = true, want false for an http_service-kind target (no specific parameter to test)")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New()
	t1 := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "comment", ParameterLocation: "query"}
	if d.Eligible(t1) {
		t.Error("Eligible = true, want false for a POST endpoint (out of scope for this phase)")
	}
}

func TestEligible_RejectsEmptyParameter(t *testing.T) {
	d := New()
	t1 := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "", ParameterLocation: ""}
	if d.Eligible(t1) {
		t.Error("Eligible = true, want false when the target names no specific parameter")
	}
}

func TestEligible_RejectsNonQueryParameterLocation(t *testing.T) {
	d := New()
	t1 := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "header"}
	if d.Eligible(t1) {
		t.Error("Eligible = true, want false for a non-query parameter location")
	}
}

// --- classifyContext ---------------------------------------------------

func TestClassifyContext_HTMLText(t *testing.T) {
	body := []byte(`<html><body><p>You searched for: sakannerXSSPROBE</p></body></html>`)
	if got := classifyContext(body, reflectionMarker); got != contextHTMLText {
		t.Errorf("classifyContext = %q, want html_text", got)
	}
}

func TestClassifyContext_HTMLAttribute(t *testing.T) {
	body := []byte(`<html><body><input type="text" value="sakannerXSSPROBE" placeholder="x"></body></html>`)
	if got := classifyContext(body, reflectionMarker); got != contextHTMLAttribute {
		t.Errorf("classifyContext = %q, want html_attribute", got)
	}
}

func TestClassifyContext_UnknownWhenMarkerAbsent(t *testing.T) {
	body := []byte(`<html><body>nothing here</body></html>`)
	if got := classifyContext(body, reflectionMarker); got != contextUnknown {
		t.Errorf("classifyContext = %q, want unknown", got)
	}
}

func TestClassifyContext_UnknownInsideComment(t *testing.T) {
	// Inside an HTML comment: an unclosed "<" (from "<!--") precedes the
	// marker, but the text doesn't end in an attribute-value quote --
	// neither the attribute nor the plain-text branch applies.
	body := []byte(`<html><body><!-- sakannerXSSPROBE --></body></html>`)
	if got := classifyContext(body, reflectionMarker); got != contextUnknown {
		t.Errorf("classifyContext = %q, want unknown", got)
	}
}

// --- Detect: reflection / encoding / context / confidence -------------

func htmlHandler(fn func(param string) string) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(fn(r.URL.Query().Get("q"))))
	}
}

func TestDetect_NotReflectedAtAll_NoFinding(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(string) string {
		return `<html><body><h1>static page, does not use q</h1></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
	if x.RequestCount() != 1 {
		t.Errorf("RequestCount() = %d, want 1 (only the reflection probe -- must stop immediately once evidence resolves the question)", x.RequestCount())
	}
}

func TestDetect_HTMLEncodedReflection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><p>You searched for: ` + html.EscapeString(q) + `</p></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding (safely encoded reflection must not be a finding)", result.Outcome)
	}
	if x.RequestCount() != 2 {
		t.Errorf("RequestCount() = %d, want 2 (reflection + context probes -- encoding only becomes visible in the context probe)", x.RequestCount())
	}
}

func TestDetect_UnrelatedStaticDecoyContent_NoFinding(t *testing.T) {
	// The page always contains XSS-payload-shaped text, regardless of q
	// -- proving the detector correlates its OWN marker, not just
	// "<script>" presence anywhere on the page.
	srv := httptest.NewServer(htmlHandler(func(string) string {
		return `<html><body><code>&lt;script&gt;alert(1)&lt;/script&gt; -- also raw: <script>legacyWidget()</script></code></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding (decoy content unrelated to the parameter must never trigger a finding)", result.Outcome)
	}
}

func TestDetect_UnescapedTextContext_HighConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><p>You searched for: ` + q + `</p></body></html>` // deliberately unescaped
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %+v, want exactly 1", result.Findings)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "reflected_xss" {
		t.Errorf("VulnerabilityType = %q, want reflected_xss", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9 (full validation payload survived verbatim)", f.Confidence)
	}
	if f.AffectedParameter != "q" {
		t.Errorf("AffectedParameter = %q, want q", f.AffectedParameter)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("Evidence = %+v, want 1 item", f.Evidence)
	}
	if f.Evidence[0].Content == "" {
		t.Error("Evidence[0].Content is empty")
	}
	if x.RequestCount() != 3 {
		t.Errorf("RequestCount() = %d, want 3 (reflection + context + validation)", x.RequestCount())
	}
}

func TestDetect_AttributeContext_HighConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><input type="text" value="` + q + `" placeholder="x"></body></html>` // deliberately unescaped
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9", f.Confidence)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
}

func TestDetect_PartialValidationFilter_MediumConfidenceFinding(t *testing.T) {
	// The small context probe's raw <>"' survives verbatim (so
	// "dangerous" is true), but this synthetic handler strips just the
	// literal "<script>"/"</script>" tag delimiters -- simulating a
	// naive filter that catches the full <script> validation payload's
	// TAG but leaves the marker text between the tags (and the smaller,
	// tagless context probe) untouched.
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		filtered := strings.ReplaceAll(q, "<script>", "")
		filtered = strings.ReplaceAll(filtered, "</script>", "")
		return `<html><body><p>You searched for: ` + filtered + `</p></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence <= 0.35 || f.Confidence >= 0.9 {
		t.Errorf("Confidence = %v, want a medium value strictly between low (0.35) and high (0.9)", f.Confidence)
	}
}

func TestDetect_UnknownContext_LowConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><!-- ` + q + ` --></body></html>` // deliberately unescaped, but inside a comment
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding (reported at low confidence, not silently dropped)", result.Outcome)
	}
	f := result.Findings[0]
	if f.Confidence >= 0.5 {
		t.Errorf("Confidence = %v, want a low value (< 0.5)", f.Confidence)
	}
	if x.RequestCount() != 2 {
		t.Errorf("RequestCount() = %d, want 2 (reflection + context only -- unknown context must not trigger a 3rd validation probe)", x.RequestCount())
	}
}

func TestDetect_NonHTMLContentType_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"q":"sakannerXSSPROBE"}`))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped (unsupported content type is NOT_APPLICABLE, not a finding)", result.Outcome)
	}
}

// --- Errors: connection failure, timeout, cancellation, scope ----------

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "q")
	srv.Close() // now nothing is listening

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
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 20 * time.Millisecond})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a slow server with a short Executor timeout: want error, got nil")
	}
}

func TestDetect_ContextCancellation_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect with a cancelled context: want error, got nil")
	}
}

func TestDetect_OutOfScope_ReturnsErrorWithoutDialing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	x := newExecutor(false, detection.ExecutorConfig{}) // denies everything

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a denied target: want error, got nil")
	}
	if hits != 0 {
		t.Errorf("server received %d requests, want 0 -- scope denial must prevent the dial entirely", hits)
	}
}

// --- Deduplication (reusing the Phase 3.1 framework, not a second mechanism) ---

func TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate(t *testing.T) {
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><p>You searched for: ` + q + `</p></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")

	first, err := d.Detect(context.Background(), tgt, newExecutor(true, detection.ExecutorConfig{}))
	if err != nil {
		t.Fatalf("first Detect: %v", err)
	}
	second, err := d.Detect(context.Background(), tgt, newExecutor(true, detection.ExecutorConfig{}))
	if err != nil {
		t.Fatalf("second Detect: %v", err)
	}

	f1 := second.Findings[0]
	f1.ID = "id-from-run-1"
	f2 := first.Findings[0]
	f2.ID = "id-from-run-2"
	f1.DetectorID, f2.DetectorID = "xss-reflected", "xss-reflected"
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

// TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests runs Detect
// concurrently against many distinct parameter targets sharing ONE
// Executor (its concurrency/rate-limit/budget controls, exactly as
// Engine.Run would use it), checking for data races (via -race) and
// that each candidate makes exactly its own expected, bounded number of
// requests -- no cross-candidate request multiplication.
func TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests(t *testing.T) {
	const candidates = 20
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		return `<html><body><p>You searched for: ` + q + `</p></body></html>` // deliberately unescaped
	}))
	defer srv.Close()

	d := New()
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "q")
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

	// 3 requests per candidate (reflection + context + validation, all
	// confirmed dangerous in this fixture) -- exactly candidates*3, no
	// more, regardless of how many ran concurrently.
	if got, want := x.RequestCount(), int64(candidates*3); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 3 probes each)", got, want, candidates)
	}
}

// TestDetect_OriginalParameterValueCannotRedirectProbesElsewhere proves
// the detector can never be tricked into contacting a host other than
// t.Host/t.IP no matter what an ATTACKER-controlled or already-discovered
// parameter value looks like (e.g. a URL pointing somewhere else) --
// requestURL only ever REPLACES t.Parameter's value in t.URL, and probe
// only ever dials through x.Do(ctx, t, ...), which is bound to t.Host/
// t.IP; nothing in this package parses a parameter's value, a
// response body, or any other input as a URL to dial. The starting
// query value here deliberately looks like a reference to an
// out-of-scope host, and the only server this test ever stands up is
// srv itself.
func TestDetect_OriginalParameterValueCannotRedirectProbesElsewhere(t *testing.T) {
	var hits int
	srv := httptest.NewServer(htmlHandler(func(q string) string {
		hits++
		return `<html><body><p>You searched for: ` + q + `</p></body></html>`
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "q")
	tgt.URL = srv.URL + "/?q=" + "http%3A%2F%2Fexternal.example%2Fevil" // the ORIGINAL discovered value looks like an out-of-scope URL
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding (the fixture itself is still vulnerable regardless of the starting parameter value)", result.Outcome)
	}
	if hits != 3 {
		t.Errorf("srv received %d requests, want exactly 3 -- all from the SAME server, proving nothing dialed the URL-shaped parameter value instead", hits)
	}
}
