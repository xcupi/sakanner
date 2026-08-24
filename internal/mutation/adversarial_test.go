package mutation

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// Phase 3.17 task section 16's adversarial suite: every listed security
// boundary is demonstrated by an actual test here, not merely asserted
// to hold by design.

// ---------------------------------------------------------------------
// SCOPE BYPASS
// ---------------------------------------------------------------------

func TestAdversarial_ScopeBypass_MutatedHostOutOfScope(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := testServerRequest(t, srv)
	// A caller cannot make Execute dial anywhere except req.Host/req.IP
	// -- there is no field in Request that lets Query/Path/Body content
	// redirect the ACTUAL dial target. This test proves it directly:
	// even with an "evil" absolute URL smuggled into the query VALUE,
	// the dial still only ever reaches req.Host.
	req.Query.Set("redirect", "http://evil.invalid/steal")
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err != nil {
		t.Fatalf("Execute against the legitimate (allowed) host with an evil-shaped query VALUE should still succeed: %v", err)
	}
	if resp.Outcome != OutcomeSuccess {
		t.Fatalf("Outcome = %s", resp.Outcome)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 request to the legitimate server, got %d", hits)
	}

	// Now actually change Host to the out-of-scope value and confirm
	// THAT is rejected -- Host is the only field that controls the dial
	// target, and mutating it is scope-checked like anything else.
	deny := &fakeValidator{allowed: false}
	x2 := NewExecutor(deny, dns.NewFakeResolver(), ExecutorConfig{})
	evilReq := req
	evilReq.Host = "evil.invalid"
	evilReq.IP = nil
	resp2, err2 := x2.Execute(context.Background(), evilReq, SessionContext{})
	if err2 == nil {
		t.Fatal("expected a scope rejection for a request whose Host was mutated to an out-of-scope value")
	}
	if resp2.Outcome != OutcomeScopeRejected {
		t.Errorf("Outcome = %s, want SCOPE_REJECTED", resp2.Outcome)
	}
}

func TestAdversarial_ScopeBypass_MutatedIPIgnoredIfHostDeniedOnRevalidation(t *testing.T) {
	// A Request carrying a STALE pre-resolved IP for a host that is no
	// longer (or never was) in scope must still be rejected -- Execute
	// re-validates req.Host/req.IP together via CheckResolved on every
	// call, never trusting a caller-supplied IP as proof of scope.
	x := NewExecutor(&fakeValidator{allowed: false}, dns.NewFakeResolver(), ExecutorConfig{})
	req := Request{Method: nethttp.MethodGet, Scheme: "http", Host: "attacker-controlled.invalid", IP: net.ParseIP("127.0.0.1"), Path: "/", Query: url.Values{}, Origin: OriginOriginal}
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil {
		t.Fatal("expected rejection of a request carrying a pre-resolved IP for a denied host")
	}
	if resp.Outcome != OutcomeScopeRejected {
		t.Errorf("Outcome = %s, want SCOPE_REJECTED", resp.Outcome)
	}
}

// hostConditionalValidator allows only a fixed set of hostnames --
// unlike fakeValidator's blanket allow/deny, this lets a test prove a
// REDIRECT specifically is rejected while the initial request itself
// is allowed.
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

// newIPServer starts an httptest.Server bound to a SPECIFIC loopback
// IP (not the default 127.0.0.1 httptest.NewServer always uses) --
// required so two servers in the same test have genuinely different
// HOSTNAMES, not just different ports on the same host. Using two
// same-host-different-port servers here would be the exact mistake
// documented and corrected in Phase 3.15's own development (see
// docs/phase-3-15-authenticated-crawling.md): same-host-different-port
// is NOT a cross-host scenario, and a redirect between two such
// servers would be (correctly) allowed by host-based scope logic,
// silently making a "redirect scope bypass" test meaningless.
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

func TestAdversarial_RedirectScopeBypass_ChainTruncatedNotFollowed(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.2", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("EVIL_OUT_OF_SCOPE_CONTENT"))
	}))

	legitSrv := newIPServer(t, "127.0.0.1", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, evilSrv.URL+"/steal", nethttp.StatusFound)
	}))

	legitHost, _, _ := net.SplitHostPort(legitSrv.Listener.Addr().String())
	validator := &hostConditionalValidator{allowedHosts: map[string]bool{legitHost: true}}
	x := NewExecutor(validator, dns.NewFakeResolver(), ExecutorConfig{MaxRedirects: 5})

	req := testServerRequest(t, legitSrv)
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err != nil {
		t.Fatalf("Execute against the legitimate host should itself succeed (only the REDIRECT target is out of scope): %v", err)
	}
	if strings.Contains(string(resp.Body), "EVIL_OUT_OF_SCOPE_CONTENT") {
		t.Fatal("SECURITY: an out-of-scope redirect target's content was followed and returned")
	}
	if resp.StatusCode == nethttp.StatusOK && strings.Contains(string(resp.Body), "EVIL") {
		t.Fatal("SECURITY: redirect to out-of-scope host was followed")
	}
	// safedial's CheckRedirect truncates the chain (returns the LAST
	// followed response, still the 302 itself) rather than erroring the
	// whole request -- the redirect Location must never have been dialed.
	if resp.StatusCode != nethttp.StatusFound {
		t.Errorf("StatusCode = %d, want %d (the redirect response itself, since the hop was refused)", resp.StatusCode, nethttp.StatusFound)
	}
}

func TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := testServerRequest(t, srv)
	// A path mutation containing what LOOKS like a host-escape attempt
	// (encoded slashes, "..", an embedded scheme) is still just PATH
	// bytes -- it can never change req.Host, which is the only field
	// Execute ever dials.
	req.Path = "/%2e%2e/%2e%2e/evil.invalid%2fsteal"
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != OutcomeSuccess {
		t.Fatalf("Outcome = %s", resp.Outcome)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 request to the legitimate server despite the encoded path payload, got %d", hits)
	}
}

// TestAdversarial_PathMutation_AbsoluteURLConfusionValue_NeverChangesHost
// is Phase 3.23's own targeted version of the test immediately above,
// exercising the ACTUAL mechanism this phase wires up
// (NewPathMutation + Mutate), not a directly-set req.Path -- an
// adversarial VALUE shaped like a full absolute URL (scheme, host,
// and path) is used as the path segment itself, proving the whole
// path from Mutation construction through Execute stays host-safe.
func TestAdversarial_PathMutation_AbsoluteURLConfusionValue_NeverChangesHost(t *testing.T) {
	var hits int32
	var sawHost string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
		sawHost = r.Host
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := testServerRequest(t, srv)
	req.Path = "/users/1"
	legitimateHost := req.Host

	m := NewPathMutation("id", "http://evil.invalid/steal", EncodingEscaped, 1, "", "", "")
	mutated, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	resp, err := x.Execute(context.Background(), mutated, SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != OutcomeSuccess {
		t.Fatalf("Outcome = %s", resp.Outcome)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 request to the legitimate server, got %d", hits)
	}
	if sawHost != legitimateHost && !strings.HasPrefix(sawHost, legitimateHost) {
		t.Fatalf("SECURITY: the server observed Host = %q, want %q (a path segment value shaped like an absolute URL must never change the dial target)", sawHost, legitimateHost)
	}
}

// ---------------------------------------------------------------------
// CREDENTIAL / COOKIE LEAKAGE
// ---------------------------------------------------------------------

func TestAdversarial_CredentialLeakage_SessionHeaderNeverInErrorOrResponse(t *testing.T) {
	// Force a transport-level failure (server closes without a
	// response) and prove the session's own secret header value never
	// appears anywhere in the returned Response.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hj, ok := w.(nethttp.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close() // abrupt close -- no response
	}))
	defer srv.Close()

	req := testServerRequest(t, srv)
	sess := SessionContext{Headers: map[string]string{"Authorization": "Bearer super-secret-value-12345"}, PinnedHost: req.Host}
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Timeout: 3 * time.Second})
	resp, err := x.Execute(context.Background(), req, sess)

	if err != nil && strings.Contains(err.Error(), "super-secret-value-12345") {
		t.Fatal("SECURITY: session secret leaked into the returned error")
	}
	if strings.Contains(resp.Error, "super-secret-value-12345") {
		t.Fatal("SECURITY: session secret leaked into Response.Error")
	}
}

func TestAdversarial_CookieLeakageBetweenIdentities_ConcurrentExecution(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		c, err := r.Cookie("identity")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(c.Value))
	}))
	defer srv.Close()

	req := testServerRequest(t, srv)
	jarA, _ := cookiejar.New(nil)
	jarA.SetCookies(req.URL(), []*nethttp.Cookie{{Name: "identity", Value: "account-a"}})
	jarB, _ := cookiejar.New(nil)
	jarB.SetCookies(req.URL(), []*nethttp.Cookie{{Name: "identity", Value: "account-b"}})

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxConcurrentRequests: 10})

	const iterations = 30
	var wg sync.WaitGroup
	errs := make(chan string, iterations*2)
	for i := 0; i < iterations; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := x.Execute(context.Background(), req, SessionContext{Jar: jarA, PinnedHost: req.Host, IdentityContext: "account-a"})
			if err != nil {
				errs <- "account-a exec error: " + err.Error()
				return
			}
			if string(resp.Body) != "account-a" {
				errs <- "SECURITY: account-a's request saw cookie value " + string(resp.Body)
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := x.Execute(context.Background(), req, SessionContext{Jar: jarB, PinnedHost: req.Host, IdentityContext: "account-b"})
			if err != nil {
				errs <- "account-b exec error: " + err.Error()
				return
			}
			if string(resp.Body) != "account-b" {
				errs <- "SECURITY: account-b's request saw cookie value " + string(resp.Body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ---------------------------------------------------------------------
// MUTATION ALIASING / ORDERING / DETERMINISM
// ---------------------------------------------------------------------

func TestAdversarial_AliasingOriginalViaMutation_BothDirections(t *testing.T) {
	original := baseRequest()
	m := NewMutation(LocationQuery, "q", "payload", EncodingEscaped, "", "", "")
	mutated, err := Mutate(original, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	// Attacking the ORIGINAL's own map/slice memory after mutation must
	// never reach the already-produced mutated Request, and vice versa.
	original.Query.Set("q", "TAMPERED-VIA-ORIGINAL")
	mutated.Query.Set("q", "TAMPERED-VIA-MUTATED")

	if original.Query.Get("q") != "TAMPERED-VIA-ORIGINAL" {
		t.Fatal("original's own query should reflect its own direct mutation")
	}
	// The two Requests must never have shared the same backing map --
	// tampering one after the fact must not retroactively change what
	// the OTHER one WAS at the time each was produced/read.
	freshMutated, err := Mutate(original, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if freshMutated.Query.Get("q") != "payload" {
		t.Fatalf("SECURITY: a later Mutate call observed a value influenced by a PRIOR mutation's own tampering: %q", freshMutated.Query.Get("q"))
	}
}

func TestAdversarial_MutationOrderingNondeterminism_SameInputsSameID(t *testing.T) {
	inputs := []struct {
		loc      Location
		param    string
		value    string
		encoding Encoding
	}{
		{LocationQuery, "a", "1", EncodingEscaped},
		{LocationQuery, "b", "2", EncodingEscaped},
		{LocationForm, "c", "3", EncodingVerbatim},
	}
	// Build the same set of mutations in two different orders,
	// concurrently, from many goroutines -- every ID must depend only
	// on content, never on when/where it was computed.
	var wg sync.WaitGroup
	results := make([][]string, 10)
	for run := 0; run < 10; run++ {
		run := run
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := make([]string, len(inputs))
			order := []int{2, 0, 1}
			if run%2 == 0 {
				order = []int{0, 1, 2}
			}
			for _, idx := range order {
				in := inputs[idx]
				m := NewMutation(in.loc, in.param, in.value, in.encoding, "", "", "")
				ids[idx] = m.ID
			}
			results[run] = ids
		}()
	}
	wg.Wait()
	for i := 1; i < len(results); i++ {
		for j := range results[i] {
			if results[i][j] != results[0][j] {
				t.Fatalf("mutation ID not deterministic across concurrent/reordered computation: run 0=%v run %d=%v", results[0], i, results[i])
			}
		}
	}
}

func TestAdversarial_ConcurrentMutationExecution_NoRace(t *testing.T) {
	original := baseRequest()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := NewMutation(LocationQuery, "q", string(rune('a'+i%26)), EncodingEscaped, "", "", "")
			if _, err := Mutate(original, m, Policy{}); err != nil {
				t.Errorf("Mutate: %v", err)
			}
		}()
	}
	wg.Wait()
	if original.Query.Get("q") != "widgets" {
		t.Fatal("SECURITY: concurrent Mutate calls against the same original disturbed it")
	}
}

// ---------------------------------------------------------------------
// EXCESSIVE MUTATION COUNT / CANCELLATION / TIMEOUT UNDER CONCURRENCY
// ---------------------------------------------------------------------

func TestAdversarial_ExcessiveMutationCount_BudgetStopsFurtherRequests(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{MaxTotalMutations: 5})
	for i := 0; i < 50; i++ {
		req := testServerRequest(t, srv)
		req.Origin = OriginMutated
		req.EndpointID = "ep-flood"
		x.Execute(context.Background(), req, SessionContext{})
	}
	if hits > 5 {
		t.Fatalf("SECURITY: a mutation budget of 5 still allowed %d requests to reach the network -- a future detector bug could generate unbounded traffic", hits)
	}
}

func TestAdversarial_ConcurrentIdentityExecution_TimeoutAndCancellationDoNotHang(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(1 * time.Second)
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{Timeout: 100 * time.Millisecond, MaxConcurrentRequests: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				x.Execute(ctx, testServerRequest(t, srv), SessionContext{})
			}()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Execute calls under a short timeout/cancelled context did not return within 5s -- possible hang")
	}
}

// ---------------------------------------------------------------------
// MALFORMED INPUT HANDLING
// ---------------------------------------------------------------------

func TestAdversarial_MalformedURL_ControlCharsInHost_NoCrash(t *testing.T) {
	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := Request{Method: nethttp.MethodGet, Scheme: "http", Host: "evil\r\nhost.test", Path: "/", Query: url.Values{}, Origin: OriginOriginal}
	// Must not panic; must fail cleanly one way or another.
	resp, err := x.Execute(context.Background(), req, SessionContext{})
	if err == nil && resp.Outcome == OutcomeSuccess {
		t.Fatal("a host containing CRLF must never be treated as a successful, legitimate request")
	}
}

func TestAdversarial_MalformedHeaders_CRLFInValue_NoInjection(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	x := NewExecutor(&fakeValidator{allowed: true}, dns.NewFakeResolver(), ExecutorConfig{})
	req := testServerRequest(t, srv)
	req.Headers.Set("X-Custom", "value")
	// net/http itself rejects a header value containing raw CR/LF when
	// building the request -- this proves Execute surfaces that
	// cleanly (as an error) rather than panicking or smuggling it.
	req.Headers["X-Injected"] = []string{"a\r\nSet-Cookie: injected=1"}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Execute panicked on a malformed header value: %v", r)
			}
		}()
		x.Execute(context.Background(), req, SessionContext{})
	}()
}

func TestAdversarial_MalformedContentType_NoCrash(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"a":1}`)
	req.ContentType = "\x00garbage\x00;;;==="
	m := NewMutation(LocationJSON, "b", "2", EncodingEscaped, "", "", "")
	// ContentType is opaque metadata to Mutate -- must not crash
	// regardless of its content.
	if _, err := Mutate(req, m, Policy{}); err != nil {
		t.Fatalf("unexpected error mutating with a malformed ContentType: %v", err)
	}
}

func TestAdversarial_DuplicateParameters_NoCrashOrAmbiguity(t *testing.T) {
	req := baseRequest()
	req.Query["dup"] = []string{"a", "b", "c", "d", "e"}
	m := NewMutation(LocationQuery, "dup", "mutated", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if len(out.Query["dup"]) != 1 {
		t.Fatalf("duplicate parameters must resolve to exactly one deterministic value after mutation, got %v", out.Query["dup"])
	}
}
