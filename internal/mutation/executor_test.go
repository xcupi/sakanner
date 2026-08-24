package mutation

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// fakeValidator lets tests control scope decisions directly -- mirrors
// internal/detection/executor_test.go's own local copy of this exact
// pattern (that package's own doc comment explains why it is kept as a
// separate, local copy per package rather than shared).
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

func testServerRequest(t *testing.T, srv *httptest.Server) Request {
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
	return Request{Method: nethttp.MethodGet, Scheme: "http", Host: host, Port: port, IP: ip, Path: "/", Query: url.Values{}, Headers: nethttp.Header{}, Origin: OriginOriginal}
}

func TestExecute_Success_ReturnsBodyAndStatus(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(nethttp.StatusTeapot)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	resp, err := x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != OutcomeSuccess {
		t.Fatalf("Outcome = %s, want SUCCESS", resp.Outcome)
	}
	if resp.StatusCode != nethttp.StatusTeapot {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
	if string(resp.Body) != "hello" {
		t.Errorf("Body = %q", resp.Body)
	}
	if resp.ContentType != "text/plain" {
		t.Errorf("ContentType = %q", resp.ContentType)
	}
}

func TestExecute_NonSuccessStatusCode_StillOutcomeSuccess(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	resp, err := x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != OutcomeSuccess {
		t.Errorf("a 500 response is a successful EXECUTION -- Outcome = %s, want SUCCESS", resp.Outcome)
	}
	if resp.StatusCode != 500 {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
}

func TestExecute_DeniedScope_NeverDials(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: false}, dns.NewFakeResolver(), ExecutorConfig{})
	resp, err := x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
	if err == nil {
		t.Fatal("expected an error for a denied target")
	}
	if resp.Outcome != OutcomeScopeRejected {
		t.Errorf("Outcome = %s, want SCOPE_REJECTED", resp.Outcome)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("SECURITY: server received %d requests, want 0 -- a denied target must never be dialed", hits)
	}
	if x.RequestCount() != 0 {
		t.Errorf("RequestCount() = %d, want 0 for a scope-rejected request", x.RequestCount())
	}
}

func TestExecute_NoPreResolvedIP_ResolvesViaResolverThenValidates(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	resolver := dns.NewFakeResolver()
	resolver.Hosts["mutation-test.invalid"] = []net.IP{net.ParseIP(host)}

	realValidator := allowExactHostValidator(t, "mutation-test.invalid")
	x := NewExecutor(realValidator, resolver, ExecutorConfig{})

	req := Request{Method: nethttp.MethodGet, Scheme: "http", Host: "mutation-test.invalid", Port: port, Path: "/", Query: url.Values{}, Headers: nethttp.Header{}, Origin: OriginOriginal}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != OutcomeSuccess || string(resp.Body) != "ok" {
		t.Fatalf("expected successful execution via resolved IP, got %+v", resp)
	}
}

func TestExecute_NoPreResolvedIP_HostNotInScope_Rejected(t *testing.T) {
	resolver := dns.NewFakeResolver()
	resolver.Hosts["never-in-scope.invalid"] = []net.IP{net.ParseIP("127.0.0.1")}
	x := NewExecutor(&fakeValidator{allowed: false}, resolver, ExecutorConfig{})

	req := Request{Method: nethttp.MethodGet, Scheme: "http", Host: "never-in-scope.invalid", Path: "/", Query: url.Values{}, Origin: OriginOriginal}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected an error for an out-of-scope host with no pre-resolved IP")
	}
	if resp.Outcome != OutcomeScopeRejected {
		t.Errorf("Outcome = %s, want SCOPE_REJECTED", resp.Outcome)
	}
}

func TestExecute_EmptyHost_InvalidRequest(t *testing.T) {
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := Request{Method: nethttp.MethodGet, Origin: OriginOriginal}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected an error for an empty host")
	}
	if resp.Outcome != OutcomeInvalidRequest {
		t.Errorf("Outcome = %s, want INVALID_REQUEST", resp.Outcome)
	}
}

func TestExecute_EmptyMethod_InvalidRequest(t *testing.T) {
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := Request{Host: "app.test", Origin: OriginOriginal}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected an error for an empty method")
	}
	if resp.Outcome != OutcomeInvalidRequest {
		t.Errorf("Outcome = %s, want INVALID_REQUEST", resp.Outcome)
	}
}

func TestExecute_OversizedRequestBody_RejectedBeforeNetworkActivity(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxRequestBodyBytes: 8})
	req := testServerRequest(t, srv)
	req.Method = nethttp.MethodPost
	req.Body = []byte("this body is way too long")

	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected an error for an oversized request body")
	}
	if resp.Outcome != OutcomeInvalidRequest {
		t.Errorf("Outcome = %s, want INVALID_REQUEST", resp.Outcome)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("server received %d requests, want 0 -- oversized body must be rejected before any network activity", hits)
	}
}

func TestExecute_OversizedResponseBody_Truncated(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write(make([]byte, 1000))
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxResponseBodyBytes: 100})
	resp, err := x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !resp.Truncated {
		t.Error("expected Truncated = true")
	}
	if len(resp.Body) != 100 {
		t.Errorf("len(Body) = %d, want exactly the 100-byte limit", len(resp.Body))
	}
}

func TestExecute_Timeout(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Timeout: 100 * time.Millisecond})
	resp, err := x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if resp.Outcome != OutcomeTimeout {
		t.Errorf("Outcome = %s, want TIMEOUT", resp.Outcome)
	}
}

func TestExecute_Cancellation(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Timeout: 10 * time.Second})
	done := make(chan struct{})
	var resp Response
	var err error
	go func() {
		resp, err = x.Execute(ctx, testServerRequest(t, srv), SessionContext{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return within 5s of cancellation")
	}
	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if resp.Outcome != OutcomeCancelled {
		t.Errorf("Outcome = %s, want CANCELLED", resp.Outcome)
	}
}

func TestExecute_ConcurrencyLimit_Bounded(t *testing.T) {
	var current, maxObserved int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		n := atomic.AddInt32(&current, 1)
		for {
			m := atomic.LoadInt32(&maxObserved)
			if n <= m || atomic.CompareAndSwapInt32(&maxObserved, m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&current, -1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxConcurrentRequests: 2})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x.Execute(context.Background(), testServerRequest(t, srv), SessionContext{})
		}()
	}
	wg.Wait()
	if maxObserved > 2 {
		t.Errorf("observed %d concurrent in-flight requests, want <= 2 (MaxConcurrentRequests)", maxObserved)
	}
}

func TestExecute_MutationBudget_PerTarget_Exhausted(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxMutationsPerTarget: 2})
	req := testServerRequest(t, srv)
	req.Origin = OriginMutated
	req.EndpointID = "ep-1"
	req.Parameter = "q"

	for i := 0; i < 2; i++ {
		if _, err := x.Execute(context.Background(), req, SessionContext{}); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected the 3rd mutated request against the same target to exceed the per-target budget")
	}
	if resp.Outcome != OutcomeInvalidRequest {
		t.Errorf("Outcome = %s, want INVALID_REQUEST", resp.Outcome)
	}
}

func TestExecute_MutationBudget_Total_Exhausted(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxTotalMutations: 3})
	for i := 0; i < 3; i++ {
		req := testServerRequest(t, srv)
		req.Origin = OriginMutated
		req.EndpointID = fmt.Sprintf("ep-%d", i) // different targets -- proves TOTAL, not per-target, is what's exhausted
		if _, err := x.Execute(context.Background(), req, SessionContext{}); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
	req := testServerRequest(t, srv)
	req.Origin = OriginMutated
	req.EndpointID = "ep-yet-another"
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected the 4th mutated request to exceed the total mutation budget, even against a brand new target")
	}
	if resp.Outcome != OutcomeInvalidRequest {
		t.Errorf("Outcome = %s, want INVALID_REQUEST", resp.Outcome)
	}
}

func TestExecute_OriginalRequests_NeverChargedAgainstMutationBudget(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxMutationsPerTarget: 1, MaxTotalMutations: 1})
	req := testServerRequest(t, srv) // Origin: OriginOriginal
	for i := 0; i < 10; i++ {
		if _, err := x.Execute(context.Background(), req, SessionContext{}); err != nil {
			t.Fatalf("original request %d unexpectedly rejected: %v", i, err)
		}
	}
}

func TestExecute_SessionHeadersAttached_HostMatch(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	req := testServerRequest(t, srv)
	sess := SessionContext{Headers: map[string]string{"Authorization": "Bearer secret-token"}, PinnedHost: req.Host}
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	if _, err := x.Execute(context.Background(), req, sess); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("server saw Authorization = %q, want session header attached for matching host", gotAuth)
	}
}

func TestExecute_SessionJarAttached_HostMatch(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(c.Value))
	}))
	defer srv.Close()

	req := testServerRequest(t, srv)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(req.URL(), []*nethttp.Cookie{{Name: "sid", Value: "session-abc"}})
	sess := SessionContext{Jar: jar, PinnedHost: req.Host}

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	resp, err := x.Execute(context.Background(), req, sess)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if string(resp.Body) != "session-abc" {
		t.Errorf("server did not see the session's cookie, got body=%q", resp.Body)
	}
}

// allowExactHostValidator builds a real scope.Validator (not a
// fakeValidator) allowing exactly one hostname -- for tests that need
// genuine CheckHost/CheckResolved behavior, not a fixed allow/deny.
func allowExactHostValidator(t *testing.T, host string) scope.Validator {
	t.Helper()
	return scope.NewValidator([]models.ScopeRule{{Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}, true)
}
