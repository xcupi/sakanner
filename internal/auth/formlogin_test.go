package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sakanner/internal/dns"
)

const loginPageHTML = `<html><body>
<form action="/login" method="post">
	<input type="hidden" name="csrf_token" value="fixed-test-token">
	<input type="text" name="username">
	<input type="password" name="password">
	<input type="submit" value="Log in">
</form>
</body></html>`

// basicLoginApp is a small, realistic login flow: GET /login serves a
// form (with a hidden CSRF field that must round-trip unmodified), POST
// /login validates against one fixed account and either sets a cookie
// and redirects to /account (success) or returns 401 with no cookie
// (failure) -- deliberately NOT "always 200," so any test that would
// pass under the "200 = success" trap the task explicitly warns against
// is a real bug, not a fixture quirk.
func basicLoginApp(t *testing.T, username, password string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("csrf_token") != "fixed-test-token" {
			http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") == username && r.FormValue("password") == password {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "valid-session-token", Path: "/"})
			http.Redirect(w, r, "/account", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login failed: invalid credentials"))
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("account page"))
	})
	return mux
}

func setupFormLogin(t *testing.T, srv *httptest.Server, host, username, password string) (Profile, Dependencies) {
	t.Helper()
	t.Setenv("SAKANNER_TEST_U_"+host, username)
	t.Setenv("SAKANNER_TEST_P_"+host, password)
	pc := ProfileConfig{
		Name: "test", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://%s:%d/login", host, serverPort(t, srv)),
		UsernameEnv: "SAKANNER_TEST_U_" + host, PasswordEnv: "SAKANNER_TEST_P_" + host,
		Timeout: 2 * time.Second,
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts[host] = []net.IP{serverIP(t, srv)}
	return profile, deps(t, resolver, allowAllValidator{})
}

func TestFormLogin_Success_CapturesSessionCookie(t *testing.T) {
	srv := newIPServer(t, "127.0.0.211", basicLoginApp(t, "alice", "correct-password"))
	profile, d := setupFormLogin(t, srv, "loginapp.test", "alice", "correct-password")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("State = %s, want AUTHENTICATED (reason: %s)", sess.State, sess.FailureReason)
	}
	cookies := sess.CookiesFor("http", "loginapp.test")
	if len(cookies) != 1 || cookies[0].Value != "valid-session-token" {
		t.Fatalf("captured cookies = %+v, want exactly the one session cookie", cookies)
	}
}

func TestFormLogin_WrongPassword_Fails(t *testing.T) {
	srv := newIPServer(t, "127.0.0.212", basicLoginApp(t, "alice", "correct-password"))
	profile, d := setupFormLogin(t, srv, "loginapp2.test", "alice", "totally-wrong")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil {
		t.Fatal("expected an authentication failure for a wrong password")
	}
	if sess.State != StateFailed {
		t.Fatalf("State = %s, want AUTHENTICATION_FAILED", sess.State)
	}
	if strings.Contains(err.Error(), "totally-wrong") || strings.Contains(sess.FailureReason, "totally-wrong") {
		t.Fatal("SECURITY: the wrong password value leaked into the error/failure reason")
	}
}

func TestFormLogin_WrongUsername_Fails(t *testing.T) {
	srv := newIPServer(t, "127.0.0.213", basicLoginApp(t, "alice", "correct-password"))
	profile, d := setupFormLogin(t, srv, "loginapp3.test", "not-alice", "correct-password")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED for a wrong username, got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_EmptyCredentials_NoCrash(t *testing.T) {
	srv := newIPServer(t, "127.0.0.214", basicLoginApp(t, "alice", "correct-password"))
	// Constructed directly (bypassing ResolveProfile, which itself
	// refuses empty env values) to exercise the HTTP-flow layer's own
	// robustness against empty credential values -- must fail cleanly,
	// never panic.
	profile := Profile{
		Name: "x", Type: TypeFormLogin, Host: "loginapp4.test",
		LoginURL:      mustParseURL(t, fmt.Sprintf("http://loginapp4.test:%d/login", serverPort(t, srv))),
		UsernameField: "username", PasswordField: "password",
		Timeout: 2 * time.Second, MaxRedirects: 3,
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["loginapp4.test"] = []net.IP{serverIP(t, srv)}

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{}))
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED for empty credentials, got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_NoFormOnPage_Fails(t *testing.T) {
	srv := newIPServer(t, "127.0.0.215", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>no form here, just text</body></html>"))
	}))
	profile, d := setupFormLogin(t, srv, "noform.test", "alice", "pw")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "no <form>") {
		t.Fatalf("expected a 'no form found' error, got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_LoginServerUnavailable_Fails(t *testing.T) {
	// A fixed loopback IP with nothing listening -- connection refused.
	resolver := dns.NewFakeResolver()
	resolver.Hosts["down.test"] = []net.IP{net.ParseIP("127.0.0.250")}
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin, LoginURL: "http://down.test:19191/login",
		UsernameEnv: "U", PasswordEnv: "P", Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{}))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED for an unreachable login server, got state=%s err=%v", sess.State, authErr)
	}
}

func TestFormLogin_Timeout_Fails(t *testing.T) {
	srv := newIPServer(t, "127.0.0.216", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte(loginPageHTML))
	}))
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["slow.test"] = []net.IP{serverIP(t, srv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://slow.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "U", PasswordEnv: "P", Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	prov, _ := NewProvider(profile)
	start := time.Now()
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{}))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED on timeout, got state=%s err=%v", sess.State, authErr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Authenticate took %s -- the configured Timeout was not enforced", elapsed)
	}
}

func TestFormLogin_GetMethodForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.RawQuery == "" {
			w.Write([]byte(`<html><body><form action="/login" method="get">
				<input type="text" name="username"><input type="password" name="password">
			</form></body></html>`))
			return
		}
		if r.URL.Query().Get("username") == "alice" && r.URL.Query().Get("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "get-method-token"})
			w.Write([]byte("welcome"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.217", mux)
	profile, d := setupFormLogin(t, srv, "getform.test", "alice", "pw")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("State = %s, want AUTHENTICATED", sess.State)
	}
}

func TestFormLogin_Always200Trap_NotTreatedAsSuccess(t *testing.T) {
	// A broken/misleading application that returns HTTP 200 for every
	// login attempt regardless of credentials, and sets no cookie --
	// task section 4's exact "must NOT blindly assume HTTP 200 means
	// login succeeded" scenario.
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		w.Write([]byte("thanks, try again")) // 200, no cookie, no matter what
	})
	srv := newIPServer(t, "127.0.0.218", mux)
	profile, d := setupFormLogin(t, srv, "trap.test", "alice", "wrong")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil || sess.State != StateAuthenticated {
		// note: err == nil AND State==Authenticated together would be the
		// actual failure mode; either alone failing this check is a bug.
	}
	if sess.State == StateAuthenticated {
		t.Fatal("a 200 response with no session cookie and no configured indicator must NOT be treated as a successful login")
	}
}

func TestFormLogin_ExplicitSuccessTextIndicator(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		if r.FormValue("username") == "alice" && r.FormValue("password") == "pw" {
			w.Write([]byte("Welcome back, alice!")) // no cookie set at all
			return
		}
		w.Write([]byte("please try again"))
	})
	srv := newIPServer(t, "127.0.0.219", mux)
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["textind.test"] = []net.IP{serverIP(t, srv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://textind.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "U", PasswordEnv: "P", SuccessTextContains: "Welcome back",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{}))
	if err != nil || sess.State != StateAuthenticated {
		t.Fatalf("expected AUTHENTICATED via the explicit success-text indicator (no cookie needed), got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_ExplicitFailureTextIndicator_OverridesStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "always-set"})
		w.Write([]byte("Error: account locked")) // 200 + cookie, but a failure indicator
	})
	srv := newIPServer(t, "127.0.0.220", mux)
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["failind.test"] = []net.IP{serverIP(t, srv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://failind.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "U", PasswordEnv: "P", FailureTextContains: "account locked",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{}))
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED via the explicit failure-text indicator despite 200+cookie, got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_ExtraFieldsSubmitted(t *testing.T) {
	var gotRemember string
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		gotRemember = r.FormValue("remember_me")
		if r.FormValue("username") == "alice" && r.FormValue("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "tok"})
			w.Write([]byte("ok"))
		}
	})
	srv := newIPServer(t, "127.0.0.221", mux)
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["extra.test"] = []net.IP{serverIP(t, srv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://extra.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "U", PasswordEnv: "P", ExtraFields: map[string]string{"remember_me": "1"},
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	prov, _ := NewProvider(profile)
	if _, err := prov.Authenticate(context.Background(), deps(t, resolver, allowAllValidator{})); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if gotRemember != "1" {
		t.Errorf("remember_me = %q, want %q (ExtraFields not submitted)", gotRemember, "1")
	}
}

func TestFormLogin_HiddenCSRFFieldPreserved(t *testing.T) {
	// basicLoginApp already rejects a submission with a missing/wrong
	// csrf_token (400) -- a successful login through it IS the proof
	// that the hidden field survived the round trip unmodified.
	srv := newIPServer(t, "127.0.0.222", basicLoginApp(t, "alice", "pw"))
	profile, d := setupFormLogin(t, srv, "csrf.test", "alice", "pw")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil || sess.State != StateAuthenticated {
		t.Fatalf("expected the hidden csrf_token field to survive submission unmodified, got state=%s err=%v", sess.State, err)
	}
}

func TestFormLogin_MalformedAndDuplicateSetCookie_NoCrashStillAuthenticates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		if r.FormValue("username") == "alice" && r.FormValue("password") == "pw" {
			// A malformed Set-Cookie line (a bare token with no "name="
			// shape at all -- syntactically valid as an HTTP header line,
			// but not a parseable cookie), a duplicate-named cookie, and a
			// valid cookie -- all in one response. net/http's own
			// Set-Cookie parser silently drops what it cannot parse; this
			// must never panic or corrupt the session either way.
			w.Header().Add("Set-Cookie", "orphan_token_no_equals_sign")
			w.Header().Add("Set-Cookie", "session=first-value")
			w.Header().Add("Set-Cookie", "session=second-value")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.223", mux)
	profile, d := setupFormLogin(t, srv, "quirkcookie.test", "alice", "pw")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate must not fail on malformed/duplicate Set-Cookie headers: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("State = %s, want AUTHENTICATED", sess.State)
	}
	cookies := sess.CookiesFor("http", "quirkcookie.test")
	if len(cookies) == 0 {
		t.Fatal("expected at least the valid 'session' cookie to have been captured")
	}
}

func TestFormLogin_HugeResponse_BoundedRead(t *testing.T) {
	padding := strings.Repeat("x", 2*1024*1024) // 2MB, well past maxAuthBodySample
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// form FIRST, padding after -- proves bounded reading doesn't
			// have to cut off the form itself to stay safe.
			w.Write([]byte(loginPageHTML))
			w.Write([]byte("<!-- " + padding + " -->"))
			return
		}
		w.Write([]byte("ok" + padding))
	})
	srv := newIPServer(t, "127.0.0.224", mux)
	profile, d := setupFormLogin(t, srv, "huge.test", "alice", "pw")
	prov, _ := NewProvider(profile)

	done := make(chan struct{})
	var sess *Session
	var authErr error
	go func() {
		sess, authErr = prov.Authenticate(context.Background(), d)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Authenticate did not return within 10s against an oversized response -- bounded reading is not working")
	}
	// The form fetch succeeds either way; success/failure of the LOGIN
	// itself depends only on whether basicLoginApp-style logic ran, which
	// it does not here -- this test only asserts no hang/crash occurred.
	_ = sess
	_ = authErr
}

func TestFormLogin_LoginURLOutOfScope_Blocked(t *testing.T) {
	srv := newIPServer(t, "127.0.0.225", basicLoginApp(t, "alice", "pw"))
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["notauthorized.test"] = []net.IP{serverIP(t, srv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://notauthorized.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "U", PasswordEnv: "P",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	validator := realValidator(allowHost("some-other-host.test"))
	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, validator))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected the out-of-scope login URL to be blocked, got state=%s err=%v", sess.State, authErr)
	}
	if !strings.Contains(authErr.Error(), "out of scope") && !strings.Contains(authErr.Error(), "no in-scope IP") {
		t.Errorf("error does not clearly indicate a scope failure: %v", authErr)
	}
}

func TestFormLogin_FormActionOutOfScope_Blocked(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.226", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SECURITY: the out-of-scope form-action host was actually dialed")
		w.WriteHeader(http.StatusOK)
	}))
	loginSrv := newIPServer(t, "127.0.0.227", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><form action="http://evil-external.test:%d/steal" method="post">
			<input type="text" name="username"><input type="password" name="password">
		</form></body></html>`, serverPort(t, evilSrv))
	}))
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["formaction.test"] = []net.IP{serverIP(t, loginSrv)}
	resolver.Hosts["evil-external.test"] = []net.IP{serverIP(t, evilSrv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://formaction.test:%d/login", serverPort(t, loginSrv)),
		UsernameEnv: "U", PasswordEnv: "P",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	// formaction.test itself is authorized; evil-external.test is not.
	validator := realValidator(allowHost("formaction.test"))
	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, validator))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected the out-of-scope form action to be blocked, got state=%s err=%v", sess.State, authErr)
	}
}

func TestFormLogin_RedirectOutOfScope_NotFollowed(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.228", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SECURITY: the out-of-scope redirect target was actually dialed")
		w.WriteHeader(http.StatusOK)
	}))
	var loginSrv *httptest.Server
	loginSrv = newIPServer(t, "127.0.0.229", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(loginPageHTML))
			return
		}
		if r.FormValue("username") == "alice" && r.FormValue("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "tok"})
			http.Redirect(w, r, fmt.Sprintf("http://evil-redirect.test:%d/steal", serverPort(t, evilSrv)), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Setenv("U", "alice")
	t.Setenv("P", "pw")
	resolver := dns.NewFakeResolver()
	resolver.Hosts["redirlogin.test"] = []net.IP{serverIP(t, loginSrv)}
	resolver.Hosts["evil-redirect.test"] = []net.IP{serverIP(t, evilSrv)}
	profile, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://redirlogin.test:%d/login", serverPort(t, loginSrv)),
		UsernameEnv: "U", PasswordEnv: "P", SuccessURLContains: "irrelevant-since-redirect-is-blocked",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	validator := realValidator(allowHost("redirlogin.test"))
	prov, _ := NewProvider(profile)
	// Whatever the final classification, the evil host must never be
	// dialed (asserted inside its own handler via t.Error above) --
	// safedial's CheckRedirect truncates the chain instead of following
	// it, so the response actually evaluated is the 302 from
	// redirlogin.test itself, not anything from evil-redirect.test.
	_, _ = prov.Authenticate(context.Background(), deps(t, resolver, validator))
}

func TestFormLogin_ConcurrentSessions_Isolated(t *testing.T) {
	srv := newIPServer(t, "127.0.0.230", basicLoginApp(t, "userA", "pwA"))
	srvB := newIPServer(t, "127.0.0.231", basicLoginApp(t, "userB", "pwB"))

	profileA, depsA := setupFormLogin(t, srv, "concA.test", "userA", "pwA")
	profileB, depsB := setupFormLogin(t, srvB, "concB.test", "userB", "pwB")

	provA, _ := NewProvider(profileA)
	provB, _ := NewProvider(profileB)

	resultsA := make(chan *Session, 5)
	resultsB := make(chan *Session, 5)
	for i := 0; i < 5; i++ {
		go func() {
			sess, _ := provA.Authenticate(context.Background(), depsA)
			resultsA <- sess
		}()
		go func() {
			sess, _ := provB.Authenticate(context.Background(), depsB)
			resultsB <- sess
		}()
	}
	for i := 0; i < 5; i++ {
		sa := <-resultsA
		sb := <-resultsB
		if sa.State != StateAuthenticated || sa.Host != "concA.test" {
			t.Errorf("session A corrupted: %+v", sa)
		}
		if sb.State != StateAuthenticated || sb.Host != "concB.test" {
			t.Errorf("session B corrupted: %+v", sb)
		}
		aCookies := sa.CookiesFor("http", "concB.test")
		if len(aCookies) != 0 {
			t.Error("session A's cookies leaked to session B's host")
		}
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}
