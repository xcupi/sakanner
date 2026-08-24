package auth

import (
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"testing"
	"time"

	"sakanner/internal/dns"
)

func setCookie(t *testing.T, jar *cookiejar.Jar, scheme, host, cookie string) {
	t.Helper()
	u := &url.URL{Scheme: scheme, Host: host, Path: "/"}
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: cookie}})
}

func TestSession_CookiesFor_HostPinned(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	setCookie(t, jar, "https", "app.test", "abc123")

	sess := &Session{Host: "app.test", Jar: jar}
	if got := sess.CookiesFor("https", "app.test"); len(got) != 1 || got[0].Value != "abc123" {
		t.Fatalf("CookiesFor(app.test) = %+v, want the one set cookie", got)
	}
	if got := sess.CookiesFor("https", "evil.test"); len(got) != 0 {
		t.Errorf("CookiesFor(evil.test) = %+v, want none -- host pinning must refuse a different host even though evil.test isn't in the jar at all", got)
	}
	if got := sess.CookiesFor("https", "APP.TEST"); len(got) != 1 {
		t.Errorf("CookiesFor is case-sensitive on host match, want case-insensitive: got %+v", got)
	}
}

func TestSession_CookiesFor_NilSessionOrNoJar(t *testing.T) {
	var nilSess *Session
	if got := nilSess.CookiesFor("https", "app.test"); got != nil {
		t.Errorf("nil session CookiesFor = %+v, want nil", got)
	}
	sess := &Session{Host: "app.test"} // no Jar
	if got := sess.CookiesFor("https", "app.test"); got != nil {
		t.Errorf("no-jar session CookiesFor = %+v, want nil", got)
	}
}

func TestSession_JarFor_HostPinned(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	setCookie(t, jar, "https", "app.test", "abc123")
	sess := &Session{Host: "app.test", Jar: jar}

	if got := sess.JarFor("app.test"); got != jar {
		t.Fatalf("JarFor(app.test) = %v, want the session's own jar", got)
	}
	if got := sess.JarFor("evil.test"); got != nil {
		t.Errorf("JarFor(evil.test) = %v, want nil (host-pinned)", got)
	}
	if got := sess.JarFor("APP.TEST"); got != jar {
		t.Error("JarFor should be case-insensitive on host match")
	}
}

func TestSession_JarFor_NilSessionOrNoJar(t *testing.T) {
	var nilSess *Session
	if got := nilSess.JarFor("app.test"); got != nil {
		t.Errorf("nil session JarFor = %v, want nil", got)
	}
	sess := &Session{Host: "app.test"}
	if got := sess.JarFor("app.test"); got != nil {
		t.Errorf("no-jar session JarFor = %v, want nil", got)
	}
}

func TestSession_HeadersFor_HostPinned(t *testing.T) {
	sess := &Session{Host: "api.test", Headers: map[string]string{"Authorization": "Bearer tok"}}
	if got := sess.HeadersFor("api.test"); got["Authorization"] != "Bearer tok" {
		t.Fatalf("HeadersFor(api.test) = %+v, want the Authorization header", got)
	}
	if got := sess.HeadersFor("other.test"); len(got) != 0 {
		t.Errorf("HeadersFor(other.test) = %+v, want none (host-pinned)", got)
	}
	// Mutating the returned copy must not affect the session.
	got := sess.HeadersFor("api.test")
	got["Authorization"] = "tampered"
	if sess.Headers["Authorization"] != "Bearer tok" {
		t.Error("HeadersFor did not return a copy -- caller mutation leaked into the session")
	}
}

func TestSession_NewClient_AttachesHeaderOnlyToPinnedHost(t *testing.T) {
	var gotAuthHeader string
	appSrv := newIPServer(t, "127.0.0.201", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	otherSrv := newIPServer(t, "127.0.0.202", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	sess := &Session{Host: "app.test", Headers: map[string]string{"Authorization": "Bearer secrettoken"}}
	d := newDialer(dns.NewFakeResolver(), allowAllValidator{})

	// Request TO the pinned host: header attached.
	client := sess.NewClient(d, "app.test", serverIP(t, appSrv), 5*time.Second, 3)
	resp, err := client.Get("http://app.test:" + strconv.Itoa(serverPort(t, appSrv)) + "/")
	if err != nil {
		t.Fatalf("GET app.test: %v", err)
	}
	resp.Body.Close()
	if gotAuthHeader != "Bearer secrettoken" {
		t.Fatalf("app.test did not receive the Authorization header: %q", gotAuthHeader)
	}

	// A client built for a DIFFERENT host must never attach it.
	gotAuthHeader = "unset"
	client2 := sess.NewClient(d, "other.test", serverIP(t, otherSrv), 5*time.Second, 3)
	resp2, err := client2.Get("http://other.test:" + strconv.Itoa(serverPort(t, otherSrv)) + "/")
	if err != nil {
		t.Fatalf("GET other.test: %v", err)
	}
	resp2.Body.Close()
	if gotAuthHeader != "" {
		t.Fatalf("Authorization header leaked to a client built for a different host: %q", gotAuthHeader)
	}
}

func TestSession_NewClient_RedirectToDifferentHost_HeaderNotForwarded(t *testing.T) {
	var evilGotAuth string
	evilSrv := newIPServer(t, "127.0.0.203", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilGotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	appSrv := newIPServer(t, "127.0.0.204", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.test:"+strconv.Itoa(serverPort(t, evilSrv))+"/", http.StatusFound)
	}))

	resolver := dns.NewFakeResolver()
	resolver.Hosts["app.test"] = []net.IP{serverIP(t, appSrv)}
	resolver.Hosts["evil.test"] = []net.IP{serverIP(t, evilSrv)}

	sess := &Session{Host: "app.test", Headers: map[string]string{"Authorization": "Bearer secrettoken"}}
	// allow-all here: this test isolates the HEADER-pinning behavior at
	// the transport layer, not scope enforcement (see
	// formlogin_test.go's out-of-scope redirect test for that layer).
	d := newDialer(resolver, allowAllValidator{})

	client := sess.NewClient(d, "app.test", serverIP(t, appSrv), 5*time.Second, 3)
	resp, err := client.Get("http://app.test:" + strconv.Itoa(serverPort(t, appSrv)) + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if evilGotAuth != "" {
		t.Fatalf("Authorization header was forwarded across a redirect to a different host: %q", evilGotAuth)
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	if (&Session{}).IsExpired(now) {
		t.Error("a session with no ExpiresAt must never be considered expired")
	}
	if !(&Session{ExpiresAt: &past}).IsExpired(now) {
		t.Error("a session with a past ExpiresAt must be expired")
	}
	if (&Session{ExpiresAt: &future}).IsExpired(now) {
		t.Error("a session with a future ExpiresAt must not be expired")
	}
	var nilSess *Session
	if nilSess.IsExpired(now) {
		t.Error("a nil session must not be considered expired")
	}
}
