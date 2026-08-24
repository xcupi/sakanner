// Phase 3.17 Request Mutation & Attack Surface Foundation: real
// internal/mutation.Executor integration against the real, already-
// isolated lab -- no new fixtures were added for this phase (task
// section 13's "add only the minimum fixtures necessary"); every
// scenario below reuses harness_auth.go's existing Phase 3.14/3.15/3.16
// page graph (login, /settings form, /api/data JSON, /items query
// parameter, two distinct real accounts).
package lab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// requestExecutorFor builds a mutation.Executor wired against l's real
// scope validator/resolver -- the exact reuse
// docs/phase-3-17-request-mutation.md section 1 requires (no private
// dialing logic reimplemented here).
func requestExecutorFor(t *testing.T, l *Lab, rules []models.ScopeRule) *mutation.Executor {
	t.Helper()
	validator := scope.NewValidator(rules, true)
	return mutation.NewExecutor(validator, l.Resolver, mutation.ExecutorConfig{Timeout: 5 * time.Second})
}

// authRequest builds a canonical mutation.Request against
// auth.scanner.test's real, scope-validated IP -- the lab-test
// equivalent of NewRequestFromTarget, since these tests exercise
// internal/mutation directly rather than through a full orchestrator
// run (BuildTargets is exercised separately by Phase 1-3.16's own
// lab suites; this phase's tests are about mutation/execution/
// comparison, not discovery).
func authRequest(t *testing.T, l *Lab, path string) mutation.Request {
	t.Helper()
	ip := dial(t, "auth.scanner.test", l)
	return mutation.Request{
		Method: http.MethodGet, Scheme: "http", Host: "auth.scanner.test", Port: mustPort(t, l.AuthAddr), IP: ip,
		Path: path, Query: url.Values{}, Headers: http.Header{}, Origin: mutation.OriginOriginal,
	}
}

// sessionContextFor adapts a real *auth.Session into the plain
// mutation.SessionContext value Execute expects -- the one-line
// adapter docs/phase-3-17-request-mutation.md section 6 describes;
// internal/mutation itself never imports internal/auth.
func sessionContextFor(sess *auth.Session, host string) mutation.SessionContext {
	return mutation.SessionContext{Jar: sess.JarFor(host), Headers: sess.HeadersFor(host), PinnedHost: host, IdentityContext: sess.IdentityName}
}

// ---------------------------------------------------------------------
// 1. ORIGINAL REQUEST (unauthenticated)
// ---------------------------------------------------------------------

func TestPhase3_17_OriginalRequest_Unauthenticated(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	x := requestExecutorFor(t, l, rules)

	req := authRequest(t, l, "/login")
	resp, err := x.Execute(context.Background(), req, mutation.SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != mutation.OutcomeSuccess || resp.StatusCode != 200 {
		t.Fatalf("Outcome=%s StatusCode=%d, want SUCCESS/200", resp.Outcome, resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "<form") {
		t.Errorf("expected the login page's form markup in the response body")
	}
}

// ---------------------------------------------------------------------
// 2. MUTATED QUERY PARAMETER + 8. RESPONSE COMPARISON (no-difference case)
// ---------------------------------------------------------------------

func TestPhase3_17_MutatedQueryParameter_AndComparison_NoDifference(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	x := requestExecutorFor(t, l, rules)
	sessCtx := sessionContextFor(sess, "auth.scanner.test")

	original := authRequest(t, l, "/items")
	original.Query.Set("category", "books")
	original.EndpointID = "ep-items"
	original.Parameter = "category"
	original.ParameterLocation = "query"

	baseline, err := x.Execute(context.Background(), original, sessCtx)
	if err != nil {
		t.Fatalf("Execute (baseline): %v", err)
	}

	m := mutation.NewMutation(mutation.LocationQuery, "category", "fiction", mutation.EncodingEscaped, original.EndpointID, "", "account-a")
	mutated, err := mutation.Mutate(original, m, mutation.Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if mutated.Query.Get("category") != "fiction" {
		t.Fatalf("mutated query = %v", mutated.Query)
	}

	probed, err := x.Execute(context.Background(), mutated, sessCtx)
	if err != nil {
		t.Fatalf("Execute (mutated): %v", err)
	}
	if !strings.Contains(string(probed.Body), "ITEMS_DATA_MARKER") {
		t.Fatalf("mutated request did not reach /items: body=%q", probed.Body)
	}

	// /items ignores the category value entirely -- a legitimate,
	// useful "no difference" comparison result: Compare must NOT claim
	// a structural difference where none exists.
	result := mutation.Compare(baseline, probed)
	if result.StructurallyDifferent {
		t.Errorf("Compare reported a structural difference for two requests that differ only in a query value /items ignores: %+v", result)
	}

	// The ORIGINAL request itself must remain untouched by the mutation.
	if original.Query.Get("category") != "books" {
		t.Errorf("SECURITY: original request's query was disturbed by Mutate: %v", original.Query)
	}
}

// ---------------------------------------------------------------------
// 3. MUTATED FORM PARAMETER
// ---------------------------------------------------------------------

func TestPhase3_17_MutatedFormParameter(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	x := requestExecutorFor(t, l, rules)
	sessCtx := sessionContextFor(sess, "auth.scanner.test")

	original := authRequest(t, l, "/settings")
	original.Method = http.MethodPost
	original.ContentType = "application/x-www-form-urlencoded"
	original.Body = []byte("csrf_token=lab-fixed-settings-csrf-token&display_name=old&theme=dark")
	original.EndpointID = "ep-settings"
	original.Parameter = "display_name"
	original.ParameterLocation = "form"

	m := mutation.NewMutation(mutation.LocationForm, "display_name", "<img src=x onerror=alert(1)>", mutation.EncodingEscaped, original.EndpointID, "", "account-a")
	mutated, err := mutation.Mutate(original, m, mutation.Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	// The mutation must not disturb the CSRF token also present in the
	// same body -- proves per-field mutation, not a body rewrite.
	if !strings.Contains(string(mutated.Body), "csrf_token=lab-fixed-settings-csrf-token") {
		t.Fatalf("form mutation disturbed an unrelated field: body=%q", mutated.Body)
	}

	resp, err := x.Execute(context.Background(), mutated, sessCtx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != mutation.OutcomeSuccess || resp.StatusCode != 200 {
		t.Fatalf("Outcome=%s StatusCode=%d body=%q, want a successful settings save (valid CSRF token preserved)", resp.Outcome, resp.StatusCode, resp.Body)
	}
}

// ---------------------------------------------------------------------
// 4/5/6. AUTHENTICATED REQUEST, IDENTITY A, IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_17_AuthenticatedRequest_IdentityAAndB_IsolatedThroughExecutor(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	x := requestExecutorFor(t, l, rules)

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	reqA := authRequest(t, l, "/api/data")
	reqA.IdentityContext = "account-a"
	reqB := reqA
	reqB.IdentityContext = "account-b"

	respA, err := x.Execute(context.Background(), reqA, mutation.SessionContext{Jar: sessA.Jar, Headers: sessA.Headers, PinnedHost: sessA.Host, IdentityContext: sessA.IdentityName})
	if err != nil {
		t.Fatalf("Execute (account-a): %v", err)
	}
	respB, err := x.Execute(context.Background(), reqB, mutation.SessionContext{Jar: sessB.Jar, Headers: sessB.Headers, PinnedHost: sessB.Host, IdentityContext: sessB.IdentityName})
	if err != nil {
		t.Fatalf("Execute (account-b): %v", err)
	}

	wantA := fmt.Sprintf(`"user_id":%d`, AccountAUserID)
	wantB := fmt.Sprintf(`"user_id":%d`, AccountBUserID)
	if !strings.Contains(string(respA.Body), wantA) {
		t.Errorf("account-a response = %q, want it to contain %q", respA.Body, wantA)
	}
	if !strings.Contains(string(respB.Body), wantB) {
		t.Errorf("account-b response = %q, want it to contain %q", respB.Body, wantB)
	}
	if strings.Contains(string(respA.Body), wantB) || strings.Contains(string(respB.Body), wantA) {
		t.Fatal("SECURITY: one identity's mutation.Executor response contains the OTHER identity's user_id")
	}
	if respA.IdentityContext != "account-a" || respB.IdentityContext != "account-b" {
		t.Errorf("Response.IdentityContext not carried through correctly: A=%q B=%q", respA.IdentityContext, respB.IdentityContext)
	}

	// 8. RESPONSE COMPARISON (difference case): same endpoint, two
	// different identities -- genuinely different response bodies
	// (different usernames), which digit-run normalization must NOT
	// erase (see docs/phase-3-17-request-mutation.md section 8's own
	// "must not over-normalize" discussion).
	result := mutation.Compare(respA, respB)
	if !result.StructurallyDifferent {
		t.Error("Compare reported no structural difference between two different identities' /api/data responses -- normalization erased a real signal")
	}
}

// ---------------------------------------------------------------------
// 7. SCOPE REJECTION
// ---------------------------------------------------------------------

func TestPhase3_17_ScopeRejection_MutatedHostNeverDialed(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules() // only auth.scanner.test -- external.scanner.test is never in scope
	x := requestExecutorFor(t, l, rules)

	req := authRequest(t, l, "/")
	req.Host = "external.scanner.test"
	req.IP = nil // force a fresh scope-validated resolve, not a stale IP

	resp, err := x.Execute(context.Background(), req, mutation.SessionContext{})
	if err == nil {
		t.Fatal("expected a scope rejection for a request mutated to an out-of-scope host")
	}
	if resp.Outcome != mutation.OutcomeScopeRejected {
		t.Errorf("Outcome = %s, want SCOPE_REJECTED", resp.Outcome)
	}
	if x.RequestCount() != 0 {
		t.Errorf("RequestCount() = %d, want 0 -- an out-of-scope host must never be dialed", x.RequestCount())
	}
}

// ---------------------------------------------------------------------
// 9. EVIDENCE / REDACTION
// ---------------------------------------------------------------------

func TestPhase3_17_Evidence_NoSessionSecretLeakage(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	x := requestExecutorFor(t, l, rules)
	sessCtx := sessionContextFor(sess, "auth.scanner.test")

	original := authRequest(t, l, "/settings")
	original.EndpointID = "ep-settings"
	original.Parameter = "csrf_token"
	original.ParameterLocation = "form"

	resp, err := x.Execute(context.Background(), original, sessCtx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	m := mutation.NewMutation(mutation.LocationForm, "csrf_token", "some-attempted-csrf-value", mutation.EncodingEscaped, original.EndpointID, "", "account-a")
	ev := detection.MutationEvidence(original, resp, &m, "baseline settings page fetch", "establishes normal authenticated behavior")

	if strings.Contains(ev.Payload, "some-attempted-csrf-value") {
		t.Fatal("SECURITY: a csrf_token-named mutation's value was not redacted in evidence Payload")
	}
	if strings.Contains(ev.Request, AccountAPassword) {
		t.Fatal("SECURITY: account password leaked into evidence Request line")
	}
	// The session cookie itself is never embedded in the canonical
	// Request at all (it lives only in SessionContext.Jar, attached at
	// the transport layer) -- so there is nothing for ToEvidence to
	// even accidentally leak here; this assertion documents that this
	// is true, not merely assumed.
	if len(original.Cookies) != 0 {
		t.Errorf("the canonical Request must never carry session cookies directly, got %v", original.Cookies)
	}
}
