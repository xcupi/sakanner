package traversalactive

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/traversal"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// --- Host safety -----------------------------------------------------------

// TestAdversarial_ProbeRequest_NeverChangesHost proves every probe's
// own dial target is always t's own host/IP/port, regardless of which
// traversal representation was injected as the PARAMETER VALUE.
func TestAdversarial_ProbeRequest_NeverChangesHost(t *testing.T) {
	var sawHost string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		vulnerableHandler(w, r)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- an injected traversal value must never change the scanner's own dial target", sawHost, tgt.Host)
	}
}

// TestAdversarial_DotSegmentsNeverCollapsedBeforeSending proves Go's
// own net/http client does not resolve/collapse ".." dot-segments
// when serializing an already-absolute request -- the one structural
// fact this package's entire probing mechanism depends on (see
// docs/phase-3-27-path-traversal-active.md section 5).
func TestAdversarial_DotSegmentsNeverCollapsedBeforeSending(t *testing.T) {
	var sawRawQuery string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawRawQuery = r.URL.RawQuery
		vulnerableHandler(w, r)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding -- if this fails, dot-segments were collapsed before the server ever saw them", result.Outcome)
	}
	if !strings.Contains(sawRawQuery, "..") && !strings.Contains(strings.ToLower(sawRawQuery), "%2e%2e") {
		t.Errorf("server's own observed RawQuery = %q, want it to contain a literal or encoded \"..\" -- the client must never collapse dot-segments itself", sawRawQuery)
	}
}

// --- Concurrent scans / independent probes ---------------------------------

func TestAdversarial_ConcurrentDetects_NoCrossContamination(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
			x := newExecutor(true, detection.ExecutorConfig{})
			result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
			if err != nil {
				errs <- fmt.Sprintf("goroutine %d: Detect error: %v", i, err)
				return
			}
			if result.Outcome != detection.OutcomeFinding {
				errs <- fmt.Sprintf("goroutine %d: Outcome = %s, want finding", i, result.Outcome)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// --- Marker false positives ------------------------------------------------

// TestAdversarial_EmptyMarker_NeverConfirms proves a misconfigured
// TraversalCase with an empty Marker can never trivially "match"
// every response.
func TestAdversarial_EmptyMarker_NeverConfirms(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	c := traversal.TraversalCase{RelativePath: "../protected/secret-marker.txt", Marker: ""}
	result, err := New([]traversal.TraversalCase{c}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: an empty configured Marker must never trivially confirm a finding")
	}
}

// --- Cancellation ------------------------------------------------------

func TestDetect_ContextCancelled_ReturnsPromptlyNoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "some response")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	result, err := New([]traversal.TraversalCase{testCase()}).Detect(ctx, tgt, x)
	if err == nil {
		t.Fatal("expected a context-cancellation/timeout error")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a cancelled context must never produce a finding")
	}
}

// --- Resource bounds -------------------------------------------------------

// TestDetect_RequestCount_Bounded proves the total number of requests
// issued per eligible target is small and bounded: 1 baseline + up to
// 4 wire variants for one configured case, never unbounded.
func TestDetect_RequestCount_Bounded(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "never matches any case")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if hits != 5 {
		t.Errorf("hits = %d, want exactly 5 (1 baseline + 4 wire variants for one case, none confirming)", hits)
	}
}

// --- Scope / redirect bypass ------------------------------------------

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

// TestDetect_RedirectToOutOfScopeHost_NeverFollowed proves a probe
// that gets redirected to an out-of-scope host -- which happens to
// serve back the exact configured marker -- never produces a finding.
// The marker's mere appearance is not, by itself, sufficient proof:
// it must appear in a response actually reachable within scope.
func TestDetect_RedirectToOutOfScopeHost_NeverFollowed(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.7", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "PATH_TRAVERSAL_SECRET_MARKER")
	}))
	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if strings.Contains(r.URL.RawQuery, "..") || strings.Contains(strings.ToLower(r.URL.RawQuery), "%2e%2e") {
			nethttp.Redirect(w, r, evilSrv.URL+"/?"+r.URL.RawQuery, nethttp.StatusFound)
			return
		}
		vulnerableHandler(w, r)
	}))

	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())
	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	x := detection.NewExecutor(validator, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5})

	tgt := targetFor(t, legitSrv, "file", "query", nethttp.MethodGet)
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a finding was produced from a marker only reachable via an out-of-scope redirect")
	}
}
