package xssactive

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// fakeValidator mirrors the same minimal test-scope-validator pattern
// already used throughout this codebase -- a local copy, since none of
// these packages export test helpers to each other.
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

// pathTargetFor mirrors targetFor, but for a Phase 3.23 path-location
// Target -- see internal/detectors/sqliactive's own identical helper.
func pathTargetFor(t *testing.T, srv *httptest.Server, param, path string, segmentIndex int) detection.Target {
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
		URL: srv.URL + path, Path: path, Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "path", PathSegmentIndex: segmentIndex,
	}
}

// --- Metadata / eligibility -------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New().Metadata()
	if meta.ID != "xss-reflected-active" {
		t.Errorf("ID = %q, want xss-reflected-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "q", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New().Eligible(tgt) {
		t.Error("expected eligible for a GET query parameter")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "q", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New().Eligible(tgt) {
		t.Error("a POST query-location target should not be eligible (matches xssreflected's own established scope)")
	}
}

func TestEligible_BodyAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "role", ParameterLocation: "body", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s body-location target", method)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

// TestEligible_FormAnyMethod_True: Phase 3.22 brings this detector to
// the same form-location coverage internal/detectors/sqliactive
// already had since Phase 3.21 -- renamed from
// TestEligible_FormLocation_False, whose own assertion this phase
// deliberately reverses (see docs/phase-3-22-active-detection-coverage.md
// section 3).
func TestEligible_PathAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodGet, nethttp.MethodPost} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "path", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s path-location target", method)
		}
	}
}

func TestEligible_FormAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "q", ParameterLocation: "form", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s form-location target", method)
		}
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "q", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

// --- Detect: query-location, HTML contexts -----------------------------

func TestDetect_QueryTextContext_UnescapedReflection_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><p>You searched for: " + q + "</p></body></html>"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "reflected_xss" {
		t.Errorf("VulnerabilityType = %q", f.VulnerabilityType)
	}
	if f.Confidence < 0.5 {
		t.Errorf("Confidence = %v, want a real (non-zero) confidence for an unescaped exact reflection", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + context probe), got %d", len(f.Evidence))
	}
}

func TestDetect_QueryAttributeContext_UnescapedReflection_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><input type="text" name="name" value="` + name + `"></body></html>`))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
}

func TestDetect_QueryHTMLEncoded_SafeNoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><p>You searched for: " + html.EscapeString(q) + "</p></body></html>"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding for an HTML-entity-encoded reflection", result.Outcome)
	}
}

func TestDetect_QueryNotReflected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Static page</h1></body></html>"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding", result.Outcome)
	}
}

func TestDetect_StaticDecoy_UnrelatedPayloadShapedText_NoFinding(t *testing.T) {
	// The page's STATIC markup already contains XSS-payload-shaped
	// text unconditionally -- a detector that just scans for
	// "<script>" anywhere rather than correlating its OWN probe marker
	// would false-positive here every time.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><code>&lt;script&gt;alert(1)&lt;/script&gt; -- also raw: <script>legacyWidget()</script></code></body></html>`))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (static decoy content unrelated to the probed parameter)", result.Outcome)
	}
}

// --- Detect: JSON body context ------------------------------------------

func TestDetect_JSONBodyReflection_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		echoed, _ := json.Marshal(map[string]string{"echo": string(body)})
		w.Header().Set("Content-Type", "application/json")
		w.Write(echoed)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a JSON response reflecting the probe marker", result.Outcome)
	}
	if result.Findings[0].Severity == "" {
		t.Error("expected a non-empty severity")
	}
	if result.Findings[0].Confidence >= 0.9 {
		t.Errorf("Confidence = %v, want LOWER confidence for a JSON-string reflection than a direct HTML/JS one", result.Findings[0].Confidence)
	}
}

func TestDetect_JSONBodyNoReflection_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding", result.Outcome)
	}
}

// --- Detect: Phase 3.22 form-location adapter ---------------------------

func TestDetect_FormBodyReflection_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", r.FormValue("q")) // deliberately unescaped
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable POST form parameter", result.Outcome)
	}
}

func TestDetect_FormBodyEscaped_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", html.EscapeString(r.FormValue("q")))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding for a safely HTML-encoded form field", result.Outcome)
	}
}

// TestDetect_FormBody_SiblingFieldsPreserved mirrors
// internal/detectors/sqliactive's own identical Phase 3.21 test: a
// form Target carrying FormFields reaches the server with every
// sibling field present, proven by the server itself asserting on a
// field OTHER than the one being mutated.
func TestDetect_FormBody_SiblingFieldsPreserved(t *testing.T) {
	var sawCSRF, sawOther string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		sawCSRF = r.FormValue("csrf_token")
		sawOther = r.FormValue("other_field")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", r.FormValue("q"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "form", nethttp.MethodPost)
	tgt.FormFields = map[string]string{"q": "test", "csrf_token": "fixed-csrf-value", "other_field": "unchanged-value"}
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawCSRF != "fixed-csrf-value" {
		t.Errorf("server saw csrf_token = %q, want fixed-csrf-value", sawCSRF)
	}
	if sawOther != "unchanged-value" {
		t.Errorf("server saw other_field = %q, want unchanged-value", sawOther)
	}
}

// --- Detect: Phase 3.23 path-location adapter ---------------------------

func TestDetect_PathSegmentReflection_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>Item: %s</p></body></html>", id) // deliberately unescaped
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "item_id", "/items/1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable path segment", result.Outcome)
	}
}

func TestDetect_PathSegmentEscaped_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>Item: %s</p></body></html>", html.EscapeString(id))
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "item_id", "/items/1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding for a safely HTML-encoded path segment", result.Outcome)
	}
}

// --- Scope enforcement ---------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(false, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for a denied-scope target")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a scope-denied target must never produce a finding")
	}
	if hits != 0 {
		t.Fatalf("SECURITY: server received %d requests despite a denied scope, want 0", hits)
	}
	if x.RequestCount() != 0 {
		t.Errorf("RequestCount() = %d, want 0", x.RequestCount())
	}
}
