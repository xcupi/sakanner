package idor

import (
	"context"
	"fmt"
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

// --- shared test helpers (mirrors sqli/xssreflected/ssrf) ---------------

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

func targetFor(t *testing.T, srv *httptest.Server, param, id string) detection.Target {
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
		URL: srv.URL + "/?" + param + "=" + id, Path: "/", Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "query",
	}
}

func ctxA() AuthContext {
	return AuthContext{ID: "user-a", Headers: map[string]string{"X-Test-Auth-User": "user-a"}, OwnsResourceIDs: map[string]bool{"resource-a": true}}
}
func ctxB() AuthContext {
	return AuthContext{ID: "user-b", Headers: map[string]string{"X-Test-Auth-User": "user-b"}, OwnsResourceIDs: map[string]bool{"resource-b": true}}
}

// vulnerableHandler returns whatever resource_id is asked for, in full,
// regardless of caller identity -- mirrors the lab's own
// /idor/api/resource/vulnerable fixture exactly.
func vulnerableHandler() nethttp.HandlerFunc {
	resources := map[string]string{"resource-a": "user-a", "resource-b": "user-b"}
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		owner, ok := resources[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"error":"not found","id":%q}`, id)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"owner":%q,"marker":"SECRET_MARKER_%s"}`, id, owner, id)
	}
}

// safeHandler verifies X-Test-Auth-User against the resource's owner.
func safeHandler() nethttp.HandlerFunc {
	resources := map[string]string{"resource-a": "user-a", "resource-b": "user-b"}
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		owner, ok := resources[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"error":"not found","id":%q}`, id)
			return
		}
		caller := r.Header.Get("X-Test-Auth-User")
		if caller != owner {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		fmt.Fprintf(w, `{"id":%q,"owner":%q,"marker":"SECRET_MARKER_%s"}`, id, owner, id)
	}
}

// --- Metadata / registration / candidate selection -----------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New([]AuthContext{ctxA(), ctxB()}).Metadata()
	if meta.ID != "idor" {
		t.Errorf("ID = %q, want idor", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
	if meta.DefaultSeverity != models.SeverityCritical {
		t.Errorf("DefaultSeverity = %q, want critical", meta.DefaultSeverity)
	}
	if len(meta.Prerequisites) == 0 {
		t.Error("Prerequisites should document the auth-context/ownership requirement")
	}
}

func TestDetector_RegistersInRegistry(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New([]AuthContext{ctxA(), ctxB()})); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d, ok := r.Get("idor")
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != "idor" {
		t.Errorf("ID = %q, want idor", d.Metadata().ID)
	}
}

func TestDetector_DuplicateRegistrationRejected(t *testing.T) {
	r := detection.NewRegistry()
	if err := r.Register(New([]AuthContext{ctxA(), ctxB()})); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(New([]AuthContext{ctxA(), ctxB()})); err == nil {
		t.Error("second Register with the same ID: want error, got nil")
	}
}

func TestEligible_ObjectReferenceParameterNames(t *testing.T) {
	d := New([]AuthContext{ctxA(), ctxB()})
	for _, name := range []string{"id", "user_id", "account_id", "order_id", "document_id", "resource_id", "ID", "Resource_Id"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: name, ParameterLocation: "query"}
		if !d.Eligible(tgt) {
			t.Errorf("Eligible(%q) = false, want true", name)
		}
	}
}

func TestEligible_RejectsNonObjectReferenceParameterName(t *testing.T) {
	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet, Parameter: "color", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible(\"color\") = true, want false")
	}
}

func TestEligible_RejectsNonEndpointTarget(t *testing.T) {
	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for an http_service-kind target")
	}
}

func TestEligible_RejectsNonGETMethod(t *testing.T) {
	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Method: nethttp.MethodPost, Parameter: "id", ParameterLocation: "query"}
	if d.Eligible(tgt) {
		t.Error("Eligible = true, want false for a POST endpoint")
	}
}

// --- Detect: end-to-end scenarios -----------------------------------------

func TestDetect_VulnerableCrossAccess_HighConfidenceFinding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	// Target discovered with resource-a's id -- owned by user-a.
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "idor" {
		t.Errorf("VulnerabilityType = %q, want idor", f.VulnerabilityType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Confidence < 0.8 {
		t.Errorf("Confidence = %v, want >= 0.8 (body matched owner's baseline)", f.Confidence)
	}
	if f.AffectedParameter != "resource_id" {
		t.Errorf("AffectedParameter = %q, want resource_id", f.AffectedParameter)
	}
	// 2 items as of Phase 3.11: the owner's own baseline access plus the
	// primary confirming cross-context probe -- see
	// docs/phase-3-11-scan-orchestrator.md "Real evidence integration".
	if len(f.Evidence) != 2 || f.Evidence[0].Content == "" || f.Evidence[1].Content == "" {
		t.Errorf("Evidence = %+v, want 2 non-empty items (baseline + probe)", f.Evidence)
	}
}

func TestDetect_SecureEndpoint_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- cross-context access is correctly denied (403)", result.Outcome)
	}
}

func TestDetect_OwnerAccessingOwnResource_NoFindingAtAll(t *testing.T) {
	// Only the owner ever requests their own resource -- Eligible still
	// applies, but there's no OTHER context to cross-test against for
	// THIS candidate alone (both contexts are configured, but this
	// single target only carries resource-a, owned by ctxA; ctxB is
	// still probed as the cross-context -- this test really just
	// confirms the "same-user resource" negative case end to end
	// against the SAFE fixture, which correctly denies ctxB).
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

// TestDetect_PublicResourceWithoutConfiguredOwnership_Skipped is the
// realistic modeling of "the application intentionally exposes public
// resources": a genuinely public resource is simply never assigned an
// owner in AuthContext.OwnsResourceIDs (an operator configuring this
// detector against a real target would not claim ownership of a
// resource that's supposed to be shared) -- so ownerOf finds no match
// and the candidate is skipped, exactly like
// TestDetect_UnconfiguredResourceID_Skipped below. If a public
// resource WERE mistakenly configured as owned by someone, this
// detector has no way to distinguish that operator error from a real
// vulnerability -- that limitation is documented in
// docs/phase-3-5-idor-bola.md "Limitations."
func TestDetect_PublicResourceWithoutConfiguredOwnership_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"public":true}`, id) // always allowed, regardless of caller
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()}) // neither context claims "resource-public"
	tgt := targetFor(t, srv, "resource_id", "resource-public")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped -- a public resource with no configured owner must never be guessed at", result.Outcome)
	}
}

func TestDetect_UnconfiguredResourceID_Skipped(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	// "resource-public" is not owned by any configured context.
	tgt := targetFor(t, srv, "resource_id", "resource-public")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped -- ownership could not be established, must not guess", result.Outcome)
	}
}

func TestDetect_FewerThanTwoContexts_Skipped(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA()}) // only 1 context
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped -- fewer than 2 contexts means no cross-context test is possible", result.Outcome)
	}
}

func TestDetect_NoContexts_Skipped(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New(nil)
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %v, want OutcomeSkipped", result.Outcome)
	}
}

func TestDetect_GenericResponseNoProtectedResourceEvidence_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) // never reflects the requested id anywhere
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- response never reflects the specific resource, not trustworthy evidence", result.Outcome)
	}
}

func TestDetect_InvalidResourceID_404NoFindingViaOwnerBaseline(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New([]AuthContext{
		{ID: "user-a", Headers: map[string]string{"X-Test-Auth-User": "user-a"}, OwnsResourceIDs: map[string]bool{"does-not-exist": true}},
		ctxB(),
	})
	tgt := targetFor(t, srv, "resource_id", "does-not-exist")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- the owner's own baseline 404s, nothing to compare against", result.Outcome)
	}
}

func TestDetect_CrossAllowedButBodyDoesNotMatch_MediumConfidenceFinding(t *testing.T) {
	// The cross context gets a 2xx, resource-specific-shaped response,
	// but it's NOT identical to the owner's own baseline -- e.g. a
	// partially-redacted or differently-shaped payload. Still access,
	// just not fully confirmed as the SAME object.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		caller := r.Header.Get("X-Test-Auth-User")
		w.Header().Set("Content-Type", "application/json")
		if caller == "user-a" {
			fmt.Fprintf(w, `{"id":%q,"owner":"user-a","marker":"FULL_SECRET"}`, id)
			return
		}
		// A different (but still allowed, still resource-id-containing) shape.
		fmt.Fprintf(w, `{"id":%q,"partial":true}`, id)
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
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

// --- Errors: 401/403/404/timeout/cancellation/scope -----------------------

func TestDetect_401Handling_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		caller := r.Header.Get("X-Test-Auth-User")
		w.Header().Set("Content-Type", "application/json")
		if caller == "" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		if caller != "user-a" {
			w.WriteHeader(401) // this fixture uses 401, not 403, for a cross-user request
			w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		fmt.Fprintf(w, `{"id":%q,"owner":"user-a"}`, id)
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a 401 must not be interpreted as IDOR", result.Outcome)
	}
}

func TestDetect_ExpiredOrInvalidCredentialContext_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	expired := AuthContext{ID: "expired-user-a", Headers: map[string]string{"X-Test-Auth-User": "expired-or-invalid-token"}, OwnsResourceIDs: map[string]bool{"resource-a": true}}
	d := New([]AuthContext{expired, ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// The "owner" context's own credentials don't actually work against
	// this fixture (its header value doesn't match "user-a") -- the
	// owner baseline itself is denied, so there's nothing to compare
	// against.
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- an invalid/expired owner credential must not produce a finding", result.Outcome)
	}
}

func TestDetect_ConnectionFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	x := newExecutor(true, detection.ExecutorConfig{})
	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a closed connection: want error, got nil")
	}
}

func TestDetect_Timeout_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"id":"resource-a"}`))
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 20 * time.Millisecond})

	_, err := d.Detect(context.Background(), tgt, x)
	if err == nil {
		t.Error("Detect against a slow server with a short Executor timeout: want error, got nil")
	}
}

func TestDetect_ContextCancellation_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"id":"resource-a"}`))
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
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
		w.Write([]byte(`{"id":"resource-a"}`))
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := d.Detect(ctx, tgt, x)
	if err == nil {
		t.Error("Detect cancelled during baseline: want error, got nil")
	}
	time.Sleep(150 * time.Millisecond)
	if got := reached.Load(); got > 1 {
		t.Errorf("server was reached %d times, want at most 1 -- cancellation during baseline must stop before the cross-context probe", got)
	}
}

func TestDetect_OutOfScope_ReturnsErrorWithoutDialing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
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
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")

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
	f1.DetectorID, f2.DetectorID = "idor", "idor"
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
	const candidates = 10
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	x := newExecutor(true, detection.ExecutorConfig{Concurrency: 8})

	results := make(chan detection.Result, candidates)
	errs := make(chan error, candidates)
	for i := 0; i < candidates; i++ {
		tgt := targetFor(t, srv, "resource_id", "resource-a")
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

	// 2 requests per candidate (owner baseline + 1 cross context, since
	// exactly 2 contexts are configured) -- exactly candidates*2, no more.
	if got, want := x.RequestCount(), int64(candidates*2); got != want {
		t.Errorf("Executor.RequestCount() = %d, want exactly %d (%d candidates x 2 requests each)", got, want, candidates)
	}
}
