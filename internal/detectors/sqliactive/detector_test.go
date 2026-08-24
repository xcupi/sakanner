package sqliactive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
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
// Target -- path (e.g. "/users/123") is the endpoint's own full,
// concrete path, and segmentIndex is the 0-based segment
// mutation.applyPath must replace.
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

// sqliRow/sqliFakeDB/sqliVulnerableHandler reproduce the exact
// error-based logic of lab/harness_vuln.go's own /sqli/vulnerable
// fixture, as a local httptest handler -- so this package's own
// integration tests do not depend on importing sakanner/lab (kept for
// the dedicated lab test files instead), while still proving Detect
// against the identical, already-reviewed vulnerability shape.
type sqliRow struct{ ID, Name string }

func sqliFakeDB() []sqliRow {
	return []sqliRow{{"1", "alice"}, {"2", "bob"}, {"3", "admin"}}
}

func sqliVulnerableQueryHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	id := r.URL.Query().Get("id")
	sqliRespond(w, id)
}

func sqliRespond(w nethttp.ResponseWriter, id string) {
	db := sqliFakeDB()
	if strings.Contains(id, "'") {
		if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
			var names []string
			for _, row := range db {
				names = append(names, row.Name)
			}
			fmt.Fprintf(w, "results: %s", strings.Join(names, ", "))
			return
		}
		w.WriteHeader(nethttp.StatusInternalServerError)
		fmt.Fprintf(w, "SQL syntax error near '%s' (simulated -- no real database exists in this fixture)", id)
		return
	}
	for _, row := range db {
		if row.ID == id {
			fmt.Fprintf(w, "results: %s", row.Name)
			return
		}
	}
	w.Write([]byte("results: (none)"))
}

func sqliSafeQueryHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	id := r.URL.Query().Get("id")
	for _, row := range sqliFakeDB() {
		if row.ID == id {
			fmt.Fprintf(w, "results: %s", row.Name)
			return
		}
	}
	w.Write([]byte("results: (none)"))
}

func sqliBooleanVulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	id := r.URL.Query().Get("id")
	db := sqliFakeDB()
	if strings.Contains(id, "'") {
		if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
			var names []string
			for _, row := range db {
				names = append(names, row.Name)
			}
			fmt.Fprintf(w, "results: %s", strings.Join(names, ", "))
			return
		}
		w.Write([]byte("results: (none)")) // no error, ever
		return
	}
	for _, row := range db {
		if row.ID == id {
			fmt.Fprintf(w, "results: %s", row.Name)
			return
		}
	}
	w.Write([]byte("results: (none)"))
}

// --- Metadata / eligibility -------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New().Metadata()
	if meta.ID != "sqli-active" {
		t.Errorf("ID = %q, want sqli-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New().Eligible(tgt) {
		t.Error("expected eligible for a GET query parameter")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New().Eligible(tgt) {
		t.Error("a POST query-location target should not be eligible")
	}
}

func TestEligible_BodyAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "body", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s body-location target", method)
		}
	}
}

func TestEligible_PathAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodGet, nethttp.MethodPost, nethttp.MethodPut} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "user_id", ParameterLocation: "path", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s path-location target", method)
		}
	}
}

func TestEligible_FormAnyMethod_True(t *testing.T) {
	for _, method := range []string{nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "form", Method: method}
		if !New().Eligible(tgt) {
			t.Errorf("expected eligible for a %s form-location target", method)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "id", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

// --- Detect: positive/negative, mirroring the real lab fixtures --------

func TestDetect_ErrorBasedVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliVulnerableQueryHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "sql_injection" {
		t.Errorf("VulnerabilityType = %q", f.VulnerabilityType)
	}
	// This fixture's error text ("SQL syntax error near '...' (simulated...)")
	// deliberately matches only the GENERIC error pattern, not a
	// specific DB family -- so the boolean-differential signal (the
	// false-condition probe also errors while the true-condition probe
	// succeeds with all rows, a genuine status-code-level difference)
	// is what drives classification here, landing in the
	// booleanDiff-confirmed tier (0.75), not the combined
	// family-specific-error-plus-boolean tier (0.95). Both are still
	// well above the "not enough evidence" threshold.
	if f.Confidence < 0.7 {
		t.Errorf("Confidence = %v, want a solidly confirmed confidence (boolean-differential tier) for a real injection", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + probe), got %d", len(f.Evidence))
	}
}

func TestDetect_MySQLFamilyErrorPlusBoolean_TopConfidenceTier(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
			w.Write([]byte("results: alice, bob, admin"))
			return
		}
		if strings.Contains(id, "'") {
			w.WriteHeader(nethttp.StatusInternalServerError)
			w.Write([]byte("You have an error in your SQL syntax; check the manual for the right syntax to use near '" + id + "'"))
			return
		}
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	if result.Findings[0].Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95 (family-specific MySQL error + confirmed boolean differential)", result.Findings[0].Confidence)
	}
}

func TestDetect_SafeParameterized_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliSafeQueryHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding for a properly parameterized endpoint", result.Outcome)
	}
}

func TestDetect_BooleanOnlyVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliBooleanVulnerableHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (boolean-only, no error text ever)", result.Outcome)
	}
	if result.Findings[0].Confidence >= 0.9 {
		t.Errorf("Confidence = %v, want the boolean-only tier (0.75), not the combined-signal tier", result.Findings[0].Confidence)
	}
}

func TestDetect_GenericUnconditionalError_NoFinding(t *testing.T) {
	// Mirrors lab's own /sqli/generic-error: ALWAYS a 500 with
	// database-error-shaped wording, including for the baseline --
	// must never be reported, since the error is unconditional.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusInternalServerError)
		w.Write([]byte("Database error: something went wrong processing your request. Please try again later."))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (unconditional, unrelated database error)", result.Outcome)
	}
}

func TestDetect_DynamicUnstableResponse_NoFinding(t *testing.T) {
	// Mirrors lab's own /sqli/dynamic: the response varies for reasons
	// unrelated to the parameter (an incrementing counter formatted
	// like a timestamp/request-id).
	var mu sync.Mutex
	count := 0
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		count++
		n := count
		mu.Unlock()
		fmt.Fprintf(w, "results: (none)\n<!-- server-time: 2024-01-01T00:00:%02dZ request-id: %d -->", n%60, n)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		return // acceptable: no finding is the ideal outcome
	}
	t.Errorf("a dynamic-but-unrelated response should not produce a finding, got %+v", result.Findings)
}

// --- Detect: JSON body context ------------------------------------------

func TestDetect_JSONBodyVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var body struct {
			ID string `json:"id"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		echoed := struct {
			Result string `json:"result"`
		}{}
		// Reuse the identical string-concatenation simulation.
		rec := httptest.NewRecorder()
		sqliRespond(rec, body.ID)
		echoed.Result = rec.Body.String()
		out, _ := json.Marshal(echoed)
		w.Write(out)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable JSON body parameter", result.Outcome)
	}
}

// --- Detect: Phase 3.21 form-location adapter ---------------------------

func TestDetect_FormBodyVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		sqliRespond(w, r.FormValue("id"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable POST form parameter", result.Outcome)
	}
}

func TestDetect_FormBodySafeParameterized_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		for _, row := range sqliFakeDB() {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no finding for a safely-parameterized form field", result.Outcome)
	}
}

// TestDetect_FormBody_SiblingFieldsPreserved proves task section 3/7's
// core requirement end to end: a form target carrying FormFields
// (Phase 3.21) reaches the target server with every sibling field
// present, not just the one being mutated -- proven by having the
// server itself assert on the value of a field OTHER than the one
// sqliactive targets.
func TestDetect_FormBody_SiblingFieldsPreserved(t *testing.T) {
	var sawCSRF, sawOther string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		sawCSRF = r.FormValue("csrf_token")
		sawOther = r.FormValue("other_field")
		sqliRespond(w, r.FormValue("id"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "form", nethttp.MethodPost)
	tgt.FormFields = map[string]string{"id": "1", "csrf_token": "fixed-csrf-value", "other_field": "unchanged-value"}
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawCSRF != "fixed-csrf-value" {
		t.Errorf("server saw csrf_token = %q, want fixed-csrf-value (sibling field must be preserved across every probe)", sawCSRF)
	}
	if sawOther != "unchanged-value" {
		t.Errorf("server saw other_field = %q, want unchanged-value", sawOther)
	}
}

// --- Detect: Phase 3.23 path-location adapter ---------------------------

// pathVulnerableHandler reproduces /users/{id}'s error-based SQLi
// shape via manual TrimPrefix, matching the established lab handler
// style (e.g. /idor/vulnerable/user/) rather than any router
// framework -- Go's net/http mux never sees a named path parameter.
func pathVulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/users/")
	sqliRespond(w, id)
}

func TestDetect_PathSegmentVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(pathVulnerableHandler))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "user_id", "/users/1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable path segment", result.Outcome)
	}
}

func TestDetect_PathSegmentSafeParameterized_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		for _, row := range sqliFakeDB() {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "user_id", "/users/1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding for a safely-parameterized path segment", result.Outcome)
	}
}

// TestDetect_PathSegment_RealSQLiProbes_NeverChangeHost proves host
// stability across this detector's own REAL probe set (including the
// quote-based error-probe payload, `'`, itself a syntax-breakout
// attempt) end to end against a real server, not merely by reading
// the source. A stronger, more directly adversarial test -- an
// arbitrary attacker-chosen VALUE shaped like a host/scheme-confusion
// attempt ("http://evil.example/..") used as the path segment itself
// -- lives at the mutation-engine level
// (internal/mutation.TestApplyPath_HostConfusionShapedValue_NeverChangesHost),
// since this detector's own payloads are always fixed SQLi shapes
// (quotes, tautologies), never arbitrary attacker-supplied strings.
func TestDetect_PathSegment_RealSQLiProbes_NeverChangeHost(t *testing.T) {
	var sawHost string
	var sawPath string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		sawPath = r.URL.Path
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		sqliRespond(w, id)
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "user_id", "/users/1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost != tgt.Host+":"+strconv.Itoa(tgt.Port) && sawHost != tgt.Host {
		t.Fatalf("SECURITY: the server observed Host = %q, want the original target host (a malicious path segment value must never change the dial target)", sawHost)
	}
	if !strings.HasPrefix(sawPath, "/users/") {
		t.Errorf("path lost its own endpoint prefix entirely: %q", sawPath)
	}
}

// --- Scope enforcement ---------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
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
