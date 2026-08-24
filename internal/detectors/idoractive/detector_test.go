package idoractive

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/mutation"
	"sakanner/internal/scope"
)

// fakeValidator mirrors the same minimal test-scope-validator pattern
// already used throughout this codebase (see
// internal/detectors/sqliactive/detector_test.go) -- a local copy,
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

// executorFor builds a *detection.Executor whose SessionContext
// attaches an "X-Test-Identity" header (when identity != "") pinned to
// srv's own host -- this package's test handlers use that header to
// simulate per-identity behavior (ownership checks, etc.), exactly
// mirroring how the real lab (lab/harness_authorization.go) uses a
// real session cookie for the identical purpose, just a header
// instead, since these tests build a bare httptest.Server rather than
// the full lab.
func executorFor(t *testing.T, srv *httptest.Server, allowed bool, identity string) *detection.Executor {
	t.Helper()
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	sess := mutation.SessionContext{PinnedHost: host, IdentityContext: identity}
	if identity != "" {
		sess.Headers = map[string]string{"X-Test-Identity": identity}
	}
	return detection.NewExecutorWithSession(&fakeValidator{allowed: allowed}, dns.NewFakeResolver(), detection.ExecutorConfig{}, sess)
}

func targetFor(t *testing.T, srv *httptest.Server, param, location string) detection.Target {
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
		URL: srv.URL + "/?" + param + "=1001", Path: "/", Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: location, IdentityContext: "identity-a",
	}
}

// --- Metadata / eligibility ----------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New(nil, "").Metadata()
	if meta.ID != "idor-active" {
		t.Errorf("ID = %q, want idor-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_ObjectIdentifierGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "user_id", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New(nil, "").Eligible(tgt) {
		t.Error("expected eligible for a GET, object-identifier-shaped query parameter")
	}
}

func TestEligible_NonObjectName_False(t *testing.T) {
	for _, name := range []string{"page", "sort", "version", "timestamp"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: name, ParameterLocation: "query", Method: nethttp.MethodGet}
		if New(nil, "").Eligible(tgt) {
			t.Errorf("%q should not be eligible (not object-identifier-shaped)", name)
		}
	}
}

func TestEligible_POST_False(t *testing.T) {
	// Task's own "prefer GET/HEAD/read-only" -- never a method that
	// could mutate state under another identity's session.
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "user_id", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New(nil, "").Eligible(tgt) {
		t.Error("a POST target should never be eligible for authorization testing")
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil, "").Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "user_id", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil, "").Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

func TestEligible_PathLocation_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "order_id", ParameterLocation: "path", Method: nethttp.MethodGet}
	if !New(nil, "").Eligible(tgt) {
		t.Error("expected eligible for a GET, object-identifier-shaped path parameter")
	}
}

// --- Detect: nil compare executor -----------------------------------------

func TestDetect_NilCompareExecutor_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "should never be reached")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	x := executorFor(t, srv, true, "identity-a")
	result, err := New(nil, "").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Fatalf("Outcome = %s, want skipped (nil compare executor)", result.Outcome)
	}
}

// --- Detect: the three-probe design, positive/negative -------------------

// idorVulnerableHandler simulates lab/harness_authorization.go's own
// /notes fixture: object 1001 exists and is returned to ANY caller
// (no ownership check at all); anything else 404s -- so a
// known-bad/sentinel value produces a genuinely different response,
// not merely a digit-run difference mutation.Compare's own body
// normalization would collapse away.
func idorVulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	id := r.URL.Query().Get("note_id")
	if id != "1001" {
		w.WriteHeader(nethttp.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	fmt.Fprintf(w, "<html><body>NOTE_CONTENT_MARKER_%s private note content</body></html>", id)
}

func TestDetect_HorizontalAuthorizationFailure_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(idorVulnerableHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (no ownership check at all)", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "idor" {
		t.Errorf("VulnerabilityType = %q, want idor", f.VulnerabilityType)
	}
	if f.IdentityContext != "identity-b" {
		t.Errorf("IdentityContext = %q, want the COMPARE identity (identity-b), not the baseline", f.IdentityContext)
	}
	if f.Severity == "" || f.Confidence <= 0 {
		t.Errorf("Severity/Confidence must be set, got %q/%v", f.Severity, f.Confidence)
	}
	if len(f.Evidence) != 3 {
		t.Errorf("expected 3 evidence items (baseline, cross-test, known-bad control), got %d", len(f.Evidence))
	}
	// Confidence tier: object value ("1001") is echoed verbatim in the
	// vulnerable handler's body, so this should land in the higher tier.
	if f.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9 (echoed-object-value tier)", f.Confidence)
	}
}

// idorSafeHandler simulates lab's own /documents fixture: object 1001
// exists and belongs to identity-a; any OTHER identity is 403ed.
func idorSafeHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.URL.Query().Get("note_id") != "1001" {
		w.WriteHeader(nethttp.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	if r.Header.Get("X-Test-Identity") != "identity-a" {
		w.WriteHeader(nethttp.StatusForbidden)
		fmt.Fprint(w, "forbidden")
		return
	}
	fmt.Fprint(w, "<html><body>NOTE_CONTENT_MARKER private note content</body></html>")
}

func TestDetect_SafeOwnershipCheck_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(idorSafeHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (a correctly-defended, ownership-checked endpoint)", result.Outcome)
	}
}

// idorGenericHandler simulates lab's own /ping fixture: a constant
// response regardless of the value requested or the caller's
// identity -- proves the known-bad-control mechanism correctly
// suppresses a finding here.
func idorGenericHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","marker":"GENERIC_ENVELOPE_MARKER"}`)
}

func TestDetect_GenericResponseRegardlessOfValue_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(idorGenericHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "request_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (the known-bad control returns the SAME generic envelope, so this is never trustworthy evidence)", result.Outcome)
	}
}

func TestDetect_BaselineDenied_NoFinding(t *testing.T) {
	// The BASELINE identity itself can't successfully access the
	// object (e.g. a stale/incorrect discovery, or the object was
	// removed) -- nothing to compare against, must never guess.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusForbidden)
		fmt.Fprint(w, "forbidden")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (baseline itself is not a successful object response)", result.Outcome)
	}
}

func TestDetect_CrossTestLoginRedirect_NoFinding(t *testing.T) {
	// Cross-test looks like a login/re-authentication page rather than
	// real object content -- must never be treated as successful
	// access even though it might carry a 200 status.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Header.Get("X-Test-Identity") == "identity-b" {
			fmt.Fprint(w, "<html><body><h1>Please log in</h1><form action=\"/login\"></form></body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>NOTE_CONTENT_MARKER real content</body></html>")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (cross-test response looks like a login page)", result.Outcome)
	}
}

func TestDetect_EmptyObjectResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// A 2xx with a near-empty body -- task's "empty object" case.
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (near-empty body is never trustworthy object evidence)", result.Outcome)
	}
}

// --- Scope enforcement -----------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, false, "identity-a")
	compare := executorFor(t, srv, false, "identity-b")

	result, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline)
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
