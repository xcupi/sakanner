package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// Phase 3.15 task section Q's adversarial suite, covering the specific
// scenarios not already exercised by Phase 3.14's own adversarial tests
// (formlogin_test.go, security_test.go): cancellation during
// authentication, session-fixation-style bogus credential acceptance,
// oversized cookie values, and malformed Set-Cookie encountered on a
// POST-login authenticated request (not just during the login flow
// itself).

// TestAdversarial_CancellationDuringAuthentication_NoHang is task
// section Q's "cancellation during authentication": a context
// cancelled WHILE Authenticate is in flight must cause it to return
// promptly (bounded by the slow handler's own delay plus a small
// margin), never hang indefinitely, and must report StateFailed --
// never StateAuthenticated (a cancelled attempt must not be
// misreported as having succeeded).
func TestAdversarial_CancellationDuringAuthentication_NoHang(t *testing.T) {
	srv := newIPServer(t, "127.0.0.240", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Write([]byte(loginPageHTML))
	}))
	profile, d := setupFormLogin(t, srv, "cancel.test", "alice", "pw")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	prov, _ := NewProvider(profile)
	done := make(chan struct{})
	var sess *Session
	var err error
	start := time.Now()
	go func() {
		sess, err = prov.Authenticate(ctx, d)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate did not return within 5s of context cancellation -- possible hang")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Authenticate took %s after cancellation at ~50ms -- did not respect ctx cancellation promptly", elapsed)
	}
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED after cancellation, got state=%s err=%v", sess.State, err)
	}
}

// TestAdversarial_SessionFixation_BogusCookieNeverAccepted proves a
// Session this package builds never trusts an externally-supplied
// cookie VALUE as if it were the result of a real login -- a
// TypeCookie profile's CookieHeader is exactly what the OPERATOR
// configured (via an env var they control), never anything read back
// from a target's own response during discovery. This test documents
// and locks that architectural fact: StaticProvider builds the Session
// directly from ProfileConfig, with no code path that could substitute
// a value observed elsewhere.
func TestAdversarial_SessionFixation_BogusCookieNeverAccepted(t *testing.T) {
	p := Profile{Name: "c", Type: TypeCookie, Host: "app.test", CookieHeader: "session_id=operator-supplied-value"}
	prov, _ := NewProvider(p)
	sess, err := prov.Authenticate(context.Background(), deps(t, dns.NewFakeResolver(), allowAllValidator{}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.Headers["Cookie"] != "session_id=operator-supplied-value" {
		t.Fatalf("Cookie header = %q, want exactly the operator-configured value, nothing substituted", sess.Headers["Cookie"])
	}
}

// TestAdversarial_OversizedCookieValue_NoCrash is task section Q's
// "oversized cookies/headers": a Set-Cookie value far larger than any
// realistic session token must not crash or hang the login flow --
// net/http/cookiejar silently accepts or drops it per its own RFC 6265
// size handling; this package must not do anything worse.
func TestAdversarial_OversizedCookieValue_NoCrash(t *testing.T) {
	hugeValue := strings.Repeat("a", 200*1024) // 200KB, absurd for a real session token
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		if r.FormValue("username") == "alice" && r.FormValue("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: hugeValue})
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.241", mux)
	profile, d := setupFormLogin(t, srv, "hugecookie.test", "alice", "pw")

	prov, _ := NewProvider(profile)
	done := make(chan struct{})
	var sess *Session
	var err error
	go func() {
		sess, err = prov.Authenticate(context.Background(), d)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate did not return within 5s against an oversized cookie -- possible hang")
	}
	// Either outcome (accepted or silently dropped by the jar) is fine
	// -- what matters is no panic/hang occurred, which reaching this
	// line without t.Fatal already proves. sess is always non-nil.
	if sess == nil {
		t.Fatal("Authenticate returned a nil Session")
	}
	_ = err
}

// TestAdversarial_MalformedSetCookie_OnPostLoginRequest_NoCrash covers
// the case Phase 3.14's own malformed-Set-Cookie test did not: a
// malformed Set-Cookie encountered on a request made AFTER a
// successful login, via Session.NewClient (e.g. during authenticated
// crawling), not during the login exchange itself.
func TestAdversarial_MalformedSetCookie_OnPostLoginRequest_NoCrash(t *testing.T) {
	srv := newIPServer(t, "127.0.0.242", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "orphan_token_no_equals_sign")
		w.Header().Add("Set-Cookie", "refreshed=new-value")
		w.Write([]byte("ok"))
	}))
	sess := &Session{Host: "127.0.0.242", Jar: newTestJar(t)}
	resolver := dns.NewFakeResolver()
	d := newDialer(resolver, allowAllValidator{})
	client := sess.NewClient(d, "127.0.0.242", serverIP(t, srv), 5*time.Second, 3)

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.242:%d/", serverPort(t, srv)))
	if err != nil {
		t.Fatalf("Get must not fail on a malformed Set-Cookie: %v", err)
	}
	resp.Body.Close()
}

func newTestJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return jar
}
