package sqliactive

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/mutation"
	"sakanner/internal/scope"
)

// Phase 3.20 task section 16's adversarial suite -- items not already
// covered by detector_test.go's own positive/negative cases.

// TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel is
// Phase 3.21 task section 6's own explicit requirement: "verify this
// at the HTTP/session level, not merely through labels." The session-
// attachment mechanism itself is entirely reused, unchanged, from
// Phase 3.19 (mutation.SessionContext/Executor.ExecuteMutation) --
// this test's only job is confirming that reuse holds for a
// form-location Target specifically, by inspecting the actual Cookie
// header the target server received for two independently-sessioned
// executors, not by comparing Target.IdentityContext strings.
func TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel(t *testing.T) {
	var mu sync.Mutex
	seenCookies := map[string][]string{} // identity -> observed Cookie header values, in request order
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		identity := r.Header.Get("X-Test-Identity")
		mu.Lock()
		seenCookies[identity] = append(seenCookies[identity], r.Header.Get("Cookie"))
		mu.Unlock()
		sqliRespond(w, r.FormValue("id"))
	}))
	defer srv.Close()

	newSessionedExecutor := func(identity, cookieValue string) *detection.Executor {
		jar, _ := cookiejar.New(nil)
		u, _ := url.Parse(srv.URL)
		jar.SetCookies(u, []*nethttp.Cookie{{Name: "session", Value: cookieValue}})
		sess := mutation.SessionContext{
			Jar:             jar,
			Headers:         map[string]string{"X-Test-Identity": identity},
			PinnedHost:      u.Hostname(),
			IdentityContext: identity,
		}
		return detection.NewExecutorWithSession(&fakeValidator{allowed: true}, dns.NewFakeResolver(), detection.ExecutorConfig{}, sess)
	}

	tgtA := targetFor(t, srv, "id", "form", nethttp.MethodPost)
	tgtA.IdentityContext = "account-a"
	tgtB := targetFor(t, srv, "id", "form", nethttp.MethodPost)
	tgtB.IdentityContext = "account-b"

	xA := newSessionedExecutor("account-a", "session-value-A")
	xB := newSessionedExecutor("account-b", "session-value-B")

	if _, err := New().Detect(context.Background(), tgtA, xA); err != nil {
		t.Fatalf("Detect account-a: %v", err)
	}
	if _, err := New().Detect(context.Background(), tgtB, xB); err != nil {
		t.Fatalf("Detect account-b: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	cookiesA, cookiesB := seenCookies["account-a"], seenCookies["account-b"]
	if len(cookiesA) == 0 || len(cookiesB) == 0 {
		t.Fatalf("expected the server to observe requests from both identities, got: %v", seenCookies)
	}
	for _, c := range cookiesA {
		if !strings.Contains(c, "session-value-A") {
			t.Errorf("account-a request carried cookie %q, want it to contain session-value-A", c)
		}
		if strings.Contains(c, "session-value-B") {
			t.Fatalf("SECURITY: account-a's request carried account-b's cookie: %q", c)
		}
	}
	for _, c := range cookiesB {
		if !strings.Contains(c, "session-value-B") {
			t.Errorf("account-b request carried cookie %q, want it to contain session-value-B", c)
		}
		if strings.Contains(c, "session-value-A") {
			t.Fatalf("SECURITY: account-b's request carried account-a's cookie: %q", c)
		}
	}
}

func TestDetect_URLEncodedParameterName_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliVulnerableQueryHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "weird id/name", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestDetect_NestedJSONParameter_MutatesCorrectPath(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "filter.id", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !strings.Contains(gotBody, `"filter"`) {
		t.Errorf("expected the nested 'filter' object to be created in the mutated body, got last request body: %s", gotBody)
	}
}

func TestDetect_DuplicateQueryParameterName_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Multiple values for the same key -- Detect's own mutation must
		// deterministically collapse to one, never crash.
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	tgt.URL = srv.URL + "/?id=1&id=2&id=3"
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestDetect_EmptyParameterName_HandledOrSkipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliSafeQueryHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "", "query", nethttp.MethodGet)
	if New().Eligible(tgt) {
		t.Error("a target with an empty parameter name must not be eligible")
	}
}

func TestDetect_BooleanTypedParameterValue_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(sqliSafeQueryHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "active", "query", nethttp.MethodGet)
	tgt.URL = srv.URL + "/?active=true"
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestDetect_VeryLargeResponseBody_BoundedNoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(strings.Repeat("padding ", 100000))) // ~800KB, past maxBodySample
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestDetect_MalformedHost_NoCrash(t *testing.T) {
	x := newExecutor(true, detection.ExecutorConfig{})
	tgt := detection.Target{
		Kind: detection.TargetKindEndpoint, Host: "evil\r\nhost.test", Scheme: "http",
		URL: "http://evil/", Path: "/", Method: nethttp.MethodGet, Parameter: "id", ParameterLocation: "query",
	}
	resp, err := New().Detect(context.Background(), tgt, x)
	if err == nil && resp.Outcome == detection.OutcomeFinding {
		t.Fatal("a malformed host must never produce a successful finding")
	}
}

func TestDetect_ContextCancelled_ReturnsPromptlyNoHang(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
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

func TestDetect_ExecutorTimeout_ReportedAsDetectorErrorNotFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{Timeout: 50 * time.Millisecond})

	result, err := New().Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for a probe that timed out -- matching xssactive's own established convention")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a timed-out probe must never produce a finding")
	}
}

func TestDetect_RateLimitedResponse_NoFinding(t *testing.T) {
	// A 429 for every request, identical regardless of payload -- must
	// never be mistaken for a database error or boolean differential.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusTooManyRequests)
		w.Write([]byte("rate limit exceeded, try again later"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "id", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("identical rate-limit responses must never produce a finding")
	}
}

func TestDetect_ParameterValidationError_NoFinding(t *testing.T) {
	// The application rejects ANY non-numeric id with the identical
	// 400 message -- including the syntax-breaking probe, which must
	// not be mistaken for a database error.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("id")
		for _, c := range id {
			if c < '0' || c > '9' {
				w.WriteHeader(nethttp.StatusBadRequest)
				w.Write([]byte("validation error: id must be numeric"))
				return
			}
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
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a generic input-validation error unrelated to SQL must never produce a finding")
	}
}

// --- Scope / redirect bypass --------------------------------------------

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

func TestDetect_RedirectToOutOfScopeHost_NeverFollowed(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.5", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusInternalServerError)
		w.Write([]byte("You have an error in your SQL syntax"))
	}))
	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, evilSrv.URL+"/?"+r.URL.RawQuery, nethttp.StatusFound)
	}))

	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())
	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	x := detection.NewExecutor(validator, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5})

	tgt := targetFor(t, legitSrv, "id", "query", nethttp.MethodGet)
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a finding was produced from content only reachable via an out-of-scope redirect")
	}
}

func TestDetect_SessionNeverLeaksToOutOfScopeHost(t *testing.T) {
	var gotAuthHeader string
	evilSrv := newIPServer(t, "127.0.0.6", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
	}))
	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, evilSrv.URL+"/", nethttp.StatusFound)
	}))
	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())

	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	sess := mutation.SessionContext{Headers: map[string]string{"Authorization": "Bearer secret-session-value"}, PinnedHost: legitHost}
	x := detection.NewExecutorWithSession(validator, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5}, sess)

	tgt := targetFor(t, legitSrv, "id", "query", nethttp.MethodGet)
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if strings.Contains(gotAuthHeader, "secret-session-value") {
		t.Fatal("SECURITY: session Authorization header leaked to an out-of-scope redirect target")
	}
}
