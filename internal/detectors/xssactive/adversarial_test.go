package xssactive

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/mutation"
	"sakanner/internal/scope"
)

// Phase 3.19 task section 16's adversarial suite -- items not already
// covered by detector_test.go's own positive/negative/scope-denial
// cases.

func TestDetect_EmptyParameterValue_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><p>" + q + "</p></body></html>"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	// Note: the original persisted value is irrelevant to Detect --
	// the mutation ALWAYS overwrites it with a probe value, so "empty
	// parameter" here means an endpoint whose reflection is otherwise
	// completely ordinary; this proves no special-casing around an
	// empty starting value causes a crash.
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestDetect_VeryLargeResponseBody_BoundedNoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(strings.Repeat("padding ", 100000))) // ~800KB of filler, well past maxBodySample
		w.Write([]byte(q))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// The marker/payload landed far past this detector's own
	// maxBodySample bound -- a bounded detector correctly reports no
	// finding rather than reading unboundedly to find it.
	if result.Outcome == detection.OutcomeFinding {
		t.Error("expected no finding when the reflection lands past the detector's own bounded read window")
	}
}

func TestDetect_RedirectToOutOfScopeHost_NeverFollowed(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.3", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("EVIL_CONTENT_" + r.URL.RawQuery))
	}))
	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, evilSrv.URL+"/?"+r.URL.RawQuery, nethttp.StatusFound)
	}))

	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())
	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	x := detection.NewExecutor(validator, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5})

	tgt := targetFor(t, legitSrv, "q", "query", nethttp.MethodGet)
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a finding was produced from content only reachable via an out-of-scope redirect")
	}
}

// hostConditionalValidator allows only a fixed set of hostnames --
// lets a test prove a REDIRECT specifically is rejected while the
// initial request is allowed (mirrors internal/mutation's own
// identical adversarial helper).
type hostConditionalValidator struct{ allowedHosts map[string]bool }

func (v *hostConditionalValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	if v.allowedHosts[host] {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny: " + host}, nil
}
func (v *hostConditionalValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true, Reason: "test allow (IP-level, unused by this test)"}, nil
}
func (v *hostConditionalValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return v.CheckHost(ctx, hostname)
}

func newIPServer(t *testing.T, ip string, handler nethttp.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestDetect_SessionNeverLeaksToOutOfScopeHost(t *testing.T) {
	var gotAuthHeader string
	evilSrv := newIPServer(t, "127.0.0.4", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
	}))
	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, evilSrv.URL+"/", nethttp.StatusFound)
	}))
	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())

	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	sess := mutation.SessionContext{Headers: map[string]string{"Authorization": "Bearer secret-session-value"}, PinnedHost: legitHost}
	x := detection.NewExecutorWithSession(validator, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5}, sess)

	tgt := targetFor(t, legitSrv, "q", "query", nethttp.MethodGet)
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if strings.Contains(gotAuthHeader, "secret-session-value") {
		t.Fatal("SECURITY: session Authorization header leaked to an out-of-scope redirect target")
	}
}

func TestDetect_ContextCancelled_ReturnsPromptlyNoHang(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 10 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		New().Detect(ctx, tgt, x)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Detect did not return within 5s of context cancellation -- possible hang")
	}
}

// TestDetect_ExecutorTimeout_ReportedAsDetectorErrorNotFinding proves
// a timed-out probe is surfaced as a plain Go error -- consistent with
// EVERY existing detector's own established convention
// (internal/detectors/sqli's own probe() propagates any x.Do error,
// including a timeout, straight up as a hard Detect error; this
// detector's ExecuteMutation-based probes do the same). Engine.Run
// already records such an error as a DetectorError and continues to
// the next target/detector without aborting the scan (proven by
// internal/detection's own engine tests, unmodified by this phase) --
// what THIS test proves is narrower and specific to this detector:
// a timeout is never silently swallowed as a false no_finding, and
// never produces a false finding either.
func TestDetect_ExecutorTimeout_ReportedAsDetectorErrorNotFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 50 * time.Millisecond})

	result, err := New().Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for a probe that timed out -- matching every existing detector's own established convention")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a timed-out probe must never produce a finding")
	}
}

func TestDetect_RepeatedDetect_SameTarget_DeterministicDeduplicatableFindings(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><p>" + q + "</p></body></html>"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "q", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})

	result1, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect (1st): %v", err)
	}
	result2, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect (2nd): %v", err)
	}
	if result1.Outcome != detection.OutcomeFinding || result2.Outcome != detection.OutcomeFinding {
		t.Fatalf("expected both runs to find the same finding: %s, %s", result1.Outcome, result2.Outcome)
	}
	f1, f2 := result1.Findings[0], result2.Findings[0]
	if f1.VulnerabilityType != f2.VulnerabilityType || f1.AffectedParameter != f2.AffectedParameter || f1.Severity != f2.Severity {
		t.Errorf("repeated Detect calls against the identical target produced different dedup-relevant fields: %+v vs %+v", f1, f2)
	}
}
