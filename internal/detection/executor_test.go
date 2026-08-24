package detection

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// fakeValidator lets tests control scope decisions directly, mirroring
// the same pattern internal/ports and internal/http already use for
// this (see internal/ports/ports_test.go's fakeValidator) -- kept as a
// separate, local copy here rather than shared, since none of these
// packages export test helpers to each other.
type fakeValidator struct {
	allowed bool
	calls   int32
}

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
	atomic.AddInt32(&f.calls, 1)
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

func testServerTarget(t *testing.T, srv *httptest.Server) Target {
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
	return Target{Host: host, IP: ip, Port: port, Scheme: "http", URL: srv.URL, Path: "/"}
}

func TestExecutor_DeniedScopeNeverDials(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	validator := &fakeValidator{allowed: false}
	x := NewExecutor(validator, dns.NewFakeResolver(), ExecutorConfig{})

	req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	_, err := x.Do(context.Background(), tgt, req)
	if err == nil {
		t.Fatal("Do against a denied target: want error, got nil")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("server received %d requests, want 0 -- a denied target must never be dialed", hits)
	}
	if atomic.LoadInt32(&validator.calls) == 0 {
		t.Error("scope validator was never consulted")
	}
}

func TestExecutor_AllowedRequestSucceeds(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})

	req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	resp, err := x.Do(context.Background(), tgt, req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if x.RequestCount() != 1 {
		t.Errorf("RequestCount() = %d, want 1", x.RequestCount())
	}
}

func TestExecutor_UserAgentIsSet(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{UserAgent: "sakanner-test-ua/1.0"})

	req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	resp, err := x.Do(context.Background(), tgt, req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if gotUA != "sakanner-test-ua/1.0" {
		t.Errorf("User-Agent = %q, want sakanner-test-ua/1.0", gotUA)
	}
}

func TestExecutor_RequestBudgetExhausted(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxRequests: 1})

	req1, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	resp1, err := x.Do(context.Background(), tgt, req1)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	resp1.Body.Close()

	req2, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	if _, err := x.Do(context.Background(), tgt, req2); err == nil {
		t.Error("second Do after budget exhausted: want error, got nil")
	}
}

func TestExecutor_ContextCancellationUnblocksImmediately(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	// A concurrency of 1 with the single slot already held means a
	// second Do call blocks on the semaphore -- ctx cancellation must
	// unblock it rather than waiting forever.
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Concurrency: 1})
	x.sem <- struct{}{} // occupy the only slot directly, simulating an in-flight request

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
		_, err := x.Do(ctx, tgt, req)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond) // let the goroutine reach the semaphore wait
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Do: want error after ctx cancellation, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do did not return within 2s of ctx cancellation -- it is stuck waiting on the semaphore")
	}
}

func TestExecutor_RateLimiterPacesRequests(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	tgt := testServerTarget(t, srv)
	// 5 requests/sec, burst 1: the 3rd request cannot start before
	// ~400ms after the first.
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Limiter: rate.NewLimiter(5, 1)})

	start := time.Now()
	for i := 0; i < 3; i++ {
		req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
		resp, err := x.Do(context.Background(), tgt, req)
		if err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Errorf("3 requests at 5/sec burst 1 completed in %v, want at least ~400ms -- limiter is not pacing requests", elapsed)
	}
}

func TestExecutor_NilIPIsRejectedWithoutDialing(t *testing.T) {
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	tgt := Target{Host: "no-ip.example", URL: "http://no-ip.example/"}
	req, _ := nethttp.NewRequest(nethttp.MethodGet, tgt.URL, nil)
	if _, err := x.Do(context.Background(), tgt, req); err == nil {
		t.Error("Do with a nil Target.IP: want error, got nil")
	}
}
