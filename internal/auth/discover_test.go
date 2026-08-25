package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// --- fixtures ---------------------------------------------------------

// conventionalLoginApp is test matrix item 1/2/8/9/10: a plain
// username/password form (fields literally named "username"/
// "password", matching item 2), POST (item 8), that sets a session
// cookie and redirects on success (item 9) or returns 401 with no
// cookie on failure (item 10) -- the same non-"always 200" discipline
// basicLoginApp (formlogin_test.go) already established.
func conventionalLoginApp(t *testing.T, username, password string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<html><head><title>Sign In</title></head><body>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="fixed-csrf-abc123">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Log in">
</form>
</body></html>`)
			return
		}
		if r.ParseForm(); r.FormValue("csrf_token") != "fixed-csrf-abc123" {
			http.Error(w, "bad csrf", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") == username && r.FormValue("password") == password {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "tok", Path: "/"})
			http.Redirect(w, r, "/welcome", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "login failed")
	})
	mux.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "welcome") })
	return mux
}

func setupDiscovery(t *testing.T, srv *httptest.Server, host, path, username, password string) (Profile, Dependencies) {
	t.Helper()
	uEnv, pEnv := "SAKANNER_DISC_U_"+host, "SAKANNER_DISC_P_"+host
	t.Setenv(uEnv, username)
	t.Setenv(pEnv, password)
	pc := ProfileConfig{
		Name: "test", Type: TypeFormLoginAuto,
		StartURL:    fmt.Sprintf("http://%s:%d%s", host, serverPort(t, srv), path),
		UsernameEnv: uEnv, PasswordEnv: pEnv,
		Timeout: 3 * time.Second,
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts[host] = []net.IP{serverIP(t, srv)}
	return profile, deps(t, resolver, allowAllValidator{})
}

// --- 1/2/8/9: conventional form, POST, redirect-on-success -----------

func TestDiscover_ConventionalForm_UsernamePasswordFieldsIdentifiedAndLoginSucceeds(t *testing.T) {
	srv := newIPServer(t, "127.0.0.240", conventionalLoginApp(t, "alice", "correct-pw"))
	profile, d := setupDiscovery(t, srv, "discoverapp1.test", "/login", "alice", "correct-pw")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected StateAuthenticated, got %s", sess.State)
	}
	if sess.LoginURL == nil || !strings.Contains(sess.LoginURL.String(), "/login") {
		t.Errorf("expected sess.LoginURL to reflect the discovered login page, got %v", sess.LoginURL)
	}
	if len(sess.CookiesFor("http", "discoverapp1.test")) == 0 {
		t.Error("expected a session cookie to have been captured")
	}
}

// --- 3: username field named "email", type=email + autocomplete -------

func TestDiscover_EmailTypeAndAutocomplete_IdentifiedAsUsernameField(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<html><body><form action="/account/login" method="post">
  <input type="email" name="email_address" autocomplete="email">
  <input type="password" name="secret">
  <button type="submit">Sign in</button>
</form></body></html>`)
			return
		}
		r.ParseForm()
		if r.FormValue("email_address") == "bob@example.test" && r.FormValue("secret") == "hunter2x" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.241", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp2.test", "/account/login", "bob@example.test", "hunter2x")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected StateAuthenticated (username field should have been identified via type=email/autocomplete=email), got %s: %s", sess.State, sess.FailureReason)
	}
}

// --- 4: password field with a non-standard but plausible name ---------

func TestDiscover_NonStandardPasswordFieldName_IdentifiedByTypeNotName(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// The password field is named "secretPhrase123" -- nothing
			// about the NAME suggests "password"; only type="password"
			// does. Proves detection never depends on a specific field
			// name (task's explicit "do not rely on one exact field name").
			fmt.Fprint(w, `<html><body><form action="/login" method="post">
  <input type="text" name="loginId">
  <input type="password" name="secretPhrase123">
  <input type="submit" value="Go">
</form></body></html>`)
			return
		}
		r.ParseForm()
		if r.FormValue("loginId") == "carol" && r.FormValue("secretPhrase123") == "pw-carol" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.242", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp3.test", "/login", "carol", "pw-carol")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected StateAuthenticated, got %s: %s", sess.State, sess.FailureReason)
	}
}

// --- 5: hidden CSRF token preserved -----------------------------------

func TestDiscover_HiddenCSRFToken_PreservedAcrossSubmission(t *testing.T) {
	// conventionalLoginApp already requires an exact csrf_token match
	// (rejects the submission with 400 otherwise) -- TestDiscover_
	// ConventionalForm above already proves the happy path preserves
	// it. This test proves the NEGATIVE: tampering would be caught.
	mux := http.NewServeMux()
	var lastSeenToken atomic.Value
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<html><body><form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="rotating-token-xyz">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`)
			return
		}
		r.ParseForm()
		lastSeenToken.Store(r.FormValue("csrf_token"))
		if r.FormValue("csrf_token") == "rotating-token-xyz" && r.FormValue("username") == "dave" && r.FormValue("password") == "pw-dave" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.243", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp4.test", "/login", "dave", "pw-dave")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected StateAuthenticated, got %s", sess.State)
	}
	if got := lastSeenToken.Load(); got != "rotating-token-xyz" {
		t.Errorf("expected the hidden CSRF token to round-trip unmodified, server saw %q", got)
	}
}

// --- 6/7: form action relative vs. absolute-but-same-origin -----------

func TestDiscover_RelativeFormAction_ResolvedAgainstCurrentPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/members/signin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// action is relative to /members/signin, not the site root.
			fmt.Fprint(w, `<html><body><form action="do-signin" method="post">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`)
			return
		}
		w.WriteHeader(http.StatusBadRequest) // should never be reached by GET-only assertion below
	})
	mux.HandleFunc("/members/do-signin", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("username") == "eve" && r.FormValue("password") == "pw-eve" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.244", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp5.test", "/members/signin", "eve", "pw-eve")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("relative form action %q should have resolved to /members/do-signin, got state=%s reason=%s", "do-signin", sess.State, sess.FailureReason)
	}
}

func TestDiscover_AbsoluteSameOriginFormAction_Accepted(t *testing.T) {
	var actionTemplate string
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, actionTemplate)
			return
		}
	})
	mux.HandleFunc("/login-submit", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("username") == "frank" && r.FormValue("password") == "pw-frank" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.245", mux)
	actionTemplate = fmt.Sprintf(`<html><body><form action="http://discoverapp6.test:%d/login-submit" method="post">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`, serverPort(t, srv))

	profile, d := setupDiscovery(t, srv, "discoverapp6.test", "/login", "frank", "pw-frank")
	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("an absolute SAME-ORIGIN form action should be accepted, got state=%s reason=%s", sess.State, sess.FailureReason)
	}
}

// --- 11: multiple forms, only one plausible login form -----------------

func TestDiscover_MultipleForms_OnlyPasswordBearingOneChosen(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
<form action="/search" method="get">
  <input type="text" name="q">
  <input type="submit" value="Search">
</form>
<form action="/authenticate" method="post">
  <input type="text" name="uname">
  <input type="password" name="pw">
  <input type="submit" value="Log in">
</form>
</body></html>`)
	})
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("uname") == "grace" && r.FormValue("pw") == "pw-grace" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		t.Error("the non-login (search) form was submitted -- discovery picked the wrong form")
	})
	srv := newIPServer(t, "127.0.0.246", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp7.test", "/", "grace", "pw-grace")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected the password-bearing form to be chosen over the search form, got state=%s reason=%s", sess.State, sess.FailureReason)
	}
}

// --- 12: no login form anywhere -----------------------------------------

func TestDiscover_NoLoginFormAnywhere_FailsCleanly(t *testing.T) {
	var fetchCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		fmt.Fprint(w, `<html><body><h1>Welcome</h1><p>Just a plain page, no forms.</p></body></html>`)
	})
	srv := newIPServer(t, "127.0.0.247", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp8.test", "/", "anyone", "anything")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected a clean StateFailed when no login form exists, got state=%s err=%v", sess.State, err)
	}
	if !strings.Contains(err.Error(), "no password-bearing") && !strings.Contains(err.Error(), "discovery failed") {
		t.Errorf("expected a clear 'no login form found' style error, got: %v", err)
	}
	if fetchCount.Load() > int32(maxDiscoveryPages) {
		t.Errorf("expected at most %d page fetch(es), got %d", maxDiscoveryPages, fetchCount.Load())
	}
}

// --- 13: cross-origin form action rejected ------------------------------

func TestDiscover_CrossOriginFormAction_Blocked(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.248", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SECURITY: the cross-origin form-action host was actually dialed during discovery")
	}))
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><form action="http://evil-cross-origin.test:%d/steal" method="post">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`, serverPort(t, evilSrv))
	})
	srv := newIPServer(t, "127.0.0.249", mux)

	t.Setenv("SAKANNER_DISC_U_X", "harry")
	t.Setenv("SAKANNER_DISC_P_X", "pw-harry")
	pc := ProfileConfig{
		Name: "x", Type: TypeFormLoginAuto,
		StartURL:    fmt.Sprintf("http://discoverapp9.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "SAKANNER_DISC_U_X", PasswordEnv: "SAKANNER_DISC_P_X",
		Timeout: 3 * time.Second,
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp9.test"] = []net.IP{serverIP(t, srv)}
	resolver.Hosts["evil-cross-origin.test"] = []net.IP{serverIP(t, evilSrv)}
	// discoverapp9.test itself is authorized; evil-cross-origin.test is not.
	validator := realValidator(allowHost("discoverapp9.test"))

	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, validator))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected the cross-origin form action to be blocked, got state=%s err=%v", sess.State, authErr)
	}
}

// --- login-link following (start page itself has no form) --------------

func TestDiscover_FollowsSameOriginLoginLink_WhenStartPageHasNoForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><h1>Welcome</h1><p>Please <a href="/account/login">Log In</a> to continue.</p></body></html>`)
	})
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<html><body><form action="/account/login" method="post">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`)
			return
		}
		r.ParseForm()
		if r.FormValue("username") == "ivan" && r.FormValue("password") == "pw-ivan" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := newIPServer(t, "127.0.0.250", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp10.test", "/", "ivan", "pw-ivan")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("expected discovery to follow the same-origin \"Log In\" link, got state=%s reason=%s", sess.State, sess.FailureReason)
	}
}

func TestDiscover_NeverFollowsCrossOriginLoginLink(t *testing.T) {
	evilSrv := newIPServer(t, "127.0.0.251", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SECURITY: a cross-origin 'login' link was actually followed during discovery")
	}))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><p><a href="http://evil-link-target.test:%d/login">Log In</a></p></body></html>`, serverPort(t, evilSrv))
	})
	srv := newIPServer(t, "127.0.0.252", mux)

	t.Setenv("SAKANNER_DISC_U_Y", "judy")
	t.Setenv("SAKANNER_DISC_P_Y", "pw-judy")
	pc := ProfileConfig{
		Name: "y", Type: TypeFormLoginAuto,
		StartURL:    fmt.Sprintf("http://discoverapp11.test:%d/", serverPort(t, srv)),
		UsernameEnv: "SAKANNER_DISC_U_Y", PasswordEnv: "SAKANNER_DISC_P_Y",
		Timeout: 3 * time.Second,
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp11.test"] = []net.IP{serverIP(t, srv)}
	resolver.Hosts["evil-link-target.test"] = []net.IP{serverIP(t, evilSrv)}
	validator := realValidator(allowHost("discoverapp11.test"), allowHost("evil-link-target.test"))
	// Even though BOTH hosts are in SCOPE here, the cross-origin link
	// must still never be followed -- "do not cross origins during
	// authentication discovery" is a same-origin constraint independent
	// of (stricter than) scope.

	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, validator))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected discovery to fail (no login form found on the SAME origin), got state=%s err=%v", sess.State, authErr)
	}
}

// --- 14: scope denial ---------------------------------------------------

func TestDiscover_ScopeDenied_NeverFetchesAnything(t *testing.T) {
	var fetched atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetched.Store(true)
		fmt.Fprint(w, `<html><body><form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"></form></body></html>`)
	})
	srv := newIPServer(t, "127.0.0.253", mux)

	t.Setenv("SAKANNER_DISC_U_Z", "ken")
	t.Setenv("SAKANNER_DISC_P_Z", "pw-ken")
	pc := ProfileConfig{
		Name: "z", Type: TypeFormLoginAuto,
		StartURL:    fmt.Sprintf("http://discoverapp12.test:%d/", serverPort(t, srv)),
		UsernameEnv: "SAKANNER_DISC_U_Z", PasswordEnv: "SAKANNER_DISC_P_Z",
		Timeout: 3 * time.Second,
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp12.test"] = []net.IP{serverIP(t, srv)}
	// realValidator with NO allow rule at all -- default-deny.
	validator := realValidator()

	prov, _ := NewProvider(profile)
	sess, authErr := prov.Authenticate(context.Background(), deps(t, resolver, validator))
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected the out-of-scope start_url to be blocked before any fetch, got state=%s err=%v", sess.State, authErr)
	}
	if fetched.Load() {
		t.Error("SECURITY: discovery fetched the target despite no scope rule authorizing it")
	}
}

// --- 15: credential redaction -------------------------------------------

func TestDiscover_CredentialsNeverAppearInErrorMessages(t *testing.T) {
	const secretUsername = "super-secret-username-marker"
	const secretPassword = "super-secret-password-marker"

	// A target with no login form at all -- forces a discovery-failure
	// error path, one of several places a credential COULD leak if
	// mishandled.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>no form here</body></html>`)
	})
	srv := newIPServer(t, "127.0.0.254", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp13.test", "/", secretUsername, secretPassword)

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil {
		t.Fatal("expected discovery to fail (no form)")
	}
	combined := err.Error() + " " + sess.FailureReason
	if strings.Contains(combined, secretUsername) || strings.Contains(combined, secretPassword) {
		t.Fatalf("SECURITY: a credential value leaked into an error/failure message: %q", combined)
	}

	// A target WITH a form but wrong credentials -- the login-failure
	// path, the other place a credential could leak.
	loginMux := conventionalLoginApp(t, "realuser", "realpass")
	loginSrv := newIPServer(t, "127.0.0.6", loginMux)
	profile2, d2 := setupDiscovery(t, loginSrv, "discoverapp14.test", "/login", secretUsername, secretPassword)
	prov2, _ := NewProvider(profile2)
	sess2, err2 := prov2.Authenticate(context.Background(), d2)
	if err2 == nil {
		t.Fatal("expected login to fail (wrong credentials)")
	}
	combined2 := err2.Error() + " " + sess2.FailureReason
	if strings.Contains(combined2, secretUsername) || strings.Contains(combined2, secretPassword) {
		t.Fatalf("SECURITY: a credential value leaked into a failed-login error message: %q", combined2)
	}
}

// --- 16: session isolation between identities ---------------------------

func TestDiscover_TwoIdentities_IndependentSessionsAndCookies(t *testing.T) {
	srv := newIPServer(t, "127.0.0.7", conventionalLoginApp(t, "userA", "pwA"))
	// Two independent profiles, same app, different accounts -- mirrors
	// how two Identities sharing one auth_profile with different
	// credential overrides would each resolve to their own Profile.
	t.Setenv("SAKANNER_DISC_UA", "userA")
	t.Setenv("SAKANNER_DISC_PA", "pwA")
	t.Setenv("SAKANNER_DISC_UB", "userB-does-not-exist")
	t.Setenv("SAKANNER_DISC_PB", "pwB-wrong")

	base := fmt.Sprintf("http://discoverapp15.test:%d/login", serverPort(t, srv))
	pcA, _ := ResolveProfile(ProfileConfig{Name: "a", Type: TypeFormLoginAuto, StartURL: base, UsernameEnv: "SAKANNER_DISC_UA", PasswordEnv: "SAKANNER_DISC_PA", Timeout: 3 * time.Second})
	pcB, _ := ResolveProfile(ProfileConfig{Name: "b", Type: TypeFormLoginAuto, StartURL: base, UsernameEnv: "SAKANNER_DISC_UB", PasswordEnv: "SAKANNER_DISC_PB", Timeout: 3 * time.Second})

	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp15.test"] = []net.IP{serverIP(t, srv)}
	d := deps(t, resolver, allowAllValidator{})

	provA, _ := NewProvider(pcA)
	sessA, errA := provA.Authenticate(context.Background(), d)
	if errA != nil || sessA.State != StateAuthenticated {
		t.Fatalf("identity A: expected success, got state=%s err=%v", sessA.State, errA)
	}
	provB, _ := NewProvider(pcB)
	sessB, errB := provB.Authenticate(context.Background(), d)
	if errB == nil || sessB.State != StateFailed {
		t.Fatalf("identity B: expected failure (wrong credentials), got state=%s err=%v", sessB.State, errB)
	}
	if sessA.Jar == nil || sessB.Jar != nil {
		t.Fatalf("expected A to have a cookie jar and B (failed login) to have none of its own -- got A.Jar=%v B.Jar=%v", sessA.Jar != nil, sessB.Jar != nil)
	}
	if sessA == sessB {
		t.Fatal("identity A and B must never be the same Session value")
	}
}

// --- bounded page fetches ------------------------------------------------

func TestDiscover_BoundedPageFetches_NeverExceedsMax(t *testing.T) {
	var fetchCount atomic.Int32
	mux := http.NewServeMux()
	// The start page links to FAR more "login-like" pages than
	// maxDiscoveryPages permits following -- none of them has a
	// password field either, so discovery must give up after exactly
	// maxDiscoveryPages fetches, never more.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 0; i < 10; i++ {
			fmt.Fprintf(&b, `<a href="/login-page-%d">Login option %d</a> `, i, i)
		}
		b.WriteString("</body></html>")
		fmt.Fprint(w, b.String())
	})
	for i := 0; i < 10; i++ {
		mux.HandleFunc(fmt.Sprintf("/login-page-%d", i), func(w http.ResponseWriter, r *http.Request) {
			fetchCount.Add(1)
			fmt.Fprint(w, `<html><body>no password field on this one either</body></html>`)
		})
	}
	srv := newIPServer(t, "127.0.0.8", mux)
	profile, d := setupDiscovery(t, srv, "discoverapp16.test", "/", "anyone", "anything")

	prov, _ := NewProvider(profile)
	sess, err := prov.Authenticate(context.Background(), d)
	if err == nil || sess.State != StateFailed {
		t.Fatalf("expected discovery to fail (no password field anywhere), got state=%s", sess.State)
	}
	if got := fetchCount.Load(); got > int32(maxDiscoveryPages) {
		t.Errorf("SECURITY/SAFETY: discovery fetched %d pages, exceeding the documented bound of %d", got, maxDiscoveryPages)
	}
}

// --- DiscoverOnly: preview never submits anything ------------------------

func TestDiscoverOnly_NeverIssuesAPOSTRequest(t *testing.T) {
	var sawPOST atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			sawPOST.Store(true)
		}
		fmt.Fprint(w, `<html><body><form action="/login" method="post">
  <input type="text" name="username"><input type="password" name="password">
</form></body></html>`)
	})
	srv := newIPServer(t, "127.0.0.9", mux)
	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp17.test"] = []net.IP{serverIP(t, srv)}
	startURL := mustParseURL(t, fmt.Sprintf("http://discoverapp17.test:%d/login", serverPort(t, srv)))

	result, err := DiscoverOnly(context.Background(), deps(t, resolver, allowAllValidator{}), startURL, 3*time.Second, 0)
	if err != nil {
		t.Fatalf("DiscoverOnly: %v", err)
	}
	if result.UsernameField != "username" || result.PasswordField != "password" {
		t.Errorf("unexpected discovery result: %+v", result)
	}
	if sawPOST.Load() {
		t.Fatal("SECURITY: DiscoverOnly (a preview, no credentials given) issued a POST request")
	}
}

func TestDiscoverOnly_NoLoginForm_ReturnsError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `<html><body>nothing here</body></html>`) })
	srv := newIPServer(t, "127.0.0.10", mux)
	resolver := dns.NewFakeResolver()
	resolver.Hosts["discoverapp18.test"] = []net.IP{serverIP(t, srv)}
	startURL := mustParseURL(t, fmt.Sprintf("http://discoverapp18.test:%d/", serverPort(t, srv)))

	_, err := DiscoverOnly(context.Background(), deps(t, resolver, allowAllValidator{}), startURL, 3*time.Second, 0)
	if err == nil {
		t.Fatal("expected an error when no login form exists")
	}
}
