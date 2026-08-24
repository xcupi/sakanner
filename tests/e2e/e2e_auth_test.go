// Phase 3.14 CLI end-to-end tests: `scanner auth profiles list/show`
// and `scanner scan --auth-profile <name>`, through the real built
// binary -- plain httptest fixtures only (no lab dependency needed for
// these; see lab/phase3_14_auth_test.go for the real-lab, orchestrator-
// level integration tests).
package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const e2eLoginPageHTML = `<html><body>
<form action="/login" method="post">
	<input type="hidden" name="csrf_token" value="e2e-fixed-token">
	<input type="text" name="username">
	<input type="password" name="password">
</form>
</body></html>`

// e2eLoginApp mirrors internal/auth's own basicLoginApp fixture
// (unexported there, so re-declared locally): GET /login serves a form
// with a hidden CSRF field, POST /login validates one fixed account and
// either sets a cookie + redirects to /account (success) or returns 401
// with no cookie (failure) -- never "200 regardless of credentials."
func e2eLoginApp(username, password string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A crawl always starts at "/" -- without a handler for it,
		// every authenticated-crawl test would 404 immediately and
		// discover nothing at all to follow, regardless of the rest of
		// this fixture's page graph. Links to both /login and /account
		// (matching lab/harness_auth.go's own root page): an
		// unauthenticated crawl reaches /account and observes it refuse
		// access (401, no further links); an authenticated crawl
		// reaches it, gets the real page, and follows ITS OWN link to
		// /secret.
		w.Write([]byte(`<html><body><a href="/login">login</a> <a href="/account">account</a></body></html>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(e2eLoginPageHTML))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("csrf_token") != "e2e-fixed-token" {
			http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") == username && r.FormValue("password") == password {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "e2e-session-token", Path: "/"})
			http.Redirect(w, r, "/account", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login failed: invalid credentials"))
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "e2e-session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		// Links to /secret -- an authenticated-only page reachable ONLY
		// via this authenticated response, mirroring
		// lab/harness_auth.go's own /account-to-/dashboard pattern --
		// Phase 3.15's CLI-level vertical slice
		// (TestScanCmd_ProfileWebAndAuthProfile_AuthenticatedCrawlDiscoversSecretPage)
		// proves --profile web + --auth-profile together actually crawl
		// authenticated content through the REAL binary, not just via
		// the orchestrator directly (see lab/phase3_15_authenticated_crawl_test.go
		// for that layer).
		w.Write([]byte(`<html><body>account page, welcome <a href="/secret">secret</a></body></html>`))
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "e2e-session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		w.Write([]byte(`<html><body>secret authenticated content -- SECRET_PAGE_MARKER</body></html>`))
	})
	return mux
}

func e2eSplitHostPort(t *testing.T, srv *httptest.Server) (string, string) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return host, port
}

func authConfigYAML(profileName, loginURL, userEnv, passEnv string) string {
	return fmt.Sprintf(`authentication:
  profiles:
    - name: %s
      type: form_login
      login_url: %s
      username_env: %s
      password_env: %s
`, profileName, loginURL, userEnv, passEnv)
}

func TestAuthProfilesCmd_ListAndShow(t *testing.T) {
	srv := httptest.NewServer(e2eLoginApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_AUTH_USER", "alice")
	t.Setenv("E2E_AUTH_PASS", "correct-horse-battery-staple")
	configPath := writeConfig(t, authConfigYAML("lab-user", loginURL, "E2E_AUTH_USER", "E2E_AUTH_PASS"))
	c := newCLI(t, buildBinary(t), configPath)

	listOut := c.mustRun("auth", "profiles", "list")
	for _, want := range []string{"lab-user", "form_login", host, "ready"} {
		if !strings.Contains(listOut, want) {
			t.Errorf("auth profiles list missing %q:\n%s", want, listOut)
		}
	}

	showOut := c.mustRun("auth", "profiles", "show", "lab-user")
	for _, want := range []string{"lab-user", "form_login", "Status: ready", "<REDACTED>"} {
		if !strings.Contains(showOut, want) {
			t.Errorf("auth profiles show missing %q:\n%s", want, showOut)
		}
	}
	if strings.Contains(showOut, "correct-horse-battery-staple") {
		t.Fatalf("SECURITY: auth profiles show leaked the raw password:\n%s", showOut)
	}
}

func TestAuthProfilesCmd_UnknownProfile(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	_, stderr, err := c.run("auth", "profiles", "show", "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown auth profile")
	}
	if !strings.Contains(stderr, "unknown authentication profile") {
		t.Errorf("stderr missing expected message: %q", stderr)
	}
}

func TestAuthProfilesCmd_NoneConfigured(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("auth", "profiles", "list")
	if !strings.Contains(out, "no authentication profiles configured") {
		t.Errorf("output = %q, want a 'no profiles configured' message", out)
	}
}

func TestScanCmd_AuthProfile_SuccessfulLogin(t *testing.T) {
	srv := httptest.NewServer(e2eLoginApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_AUTH_USER", "alice")
	t.Setenv("E2E_AUTH_PASS", "correct-horse-battery-staple")
	extra := authConfigYAML("lab-user", loginURL, "E2E_AUTH_USER", "E2E_AUTH_PASS") + fmt.Sprintf("ports:\n  default_ports: [%s]\n", port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host, "--auth-profile", "lab-user")
	if !strings.Contains(out, "Authentication succeeded for profile \"lab-user\"") {
		t.Errorf("output missing authentication success message:\n%s", out)
	}
	if !strings.Contains(out, "Auth:") || !strings.Contains(out, "Status:                 AUTHENTICATED") {
		t.Errorf("output missing Auth: block with AUTHENTICATED status:\n%s", out)
	}
	if !strings.Contains(out, "Scan ID:") {
		t.Errorf("output missing Scan ID -- the scan itself did not proceed:\n%s", out)
	}
}

func TestScanCmd_AuthProfile_WrongCredentials_ExitCode5_NoScanJob(t *testing.T) {
	srv := httptest.NewServer(e2eLoginApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_AUTH_USER", "alice")
	t.Setenv("E2E_AUTH_PASS", "totally-the-wrong-password")
	configPath := writeConfig(t, authConfigYAML("lab-user", loginURL, "E2E_AUTH_USER", "E2E_AUTH_PASS"))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out, _, err := c.run("scan", host, "--auth-profile", "lab-user")
	if err == nil {
		t.Fatalf("expected the scan to fail for wrong credentials\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if !strings.Contains(out, "Authentication FAILED") {
		t.Errorf("output missing authentication failure message:\n%s", out)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite authentication failing -- task section 12 requires none:\n%s", out)
	}
	if strings.Contains(out, "totally-the-wrong-password") {
		t.Fatal("SECURITY: the wrong password leaked into scan output")
	}
}

func TestScanCmd_AuthProfile_UnknownProfileName_ExitCode5_NoScanJob(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, _, err := c.run("scan", "example.test", "--auth-profile", "does-not-exist")
	if err == nil {
		t.Fatalf("expected an error for an unknown --auth-profile\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite an unknown auth profile:\n%s", out)
	}
}

// TestScanCmd_ProfileWebAndAuthProfile_AuthenticatedCrawlDiscoversSecretPage
// is Phase 3.15 task section A's vertical slice through the REAL CLI
// binary: "--profile web --auth-profile <name>" together. /secret is
// reachable ONLY via a link inside /account's authenticated response,
// so its presence in the report's endpoint list is direct proof this
// combination actually performs authenticated crawling end to end, not
// just authentication with an unrelated (e.g. recon, crawler-disabled)
// profile -- the gap TestScanCmd_AuthProfile_SuccessfulLogin (which
// uses no --profile, so the crawler never runs at all) does not cover.
func TestScanCmd_ProfileWebAndAuthProfile_AuthenticatedCrawlDiscoversSecretPage(t *testing.T) {
	srv := httptest.NewServer(e2eLoginApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_AUTH_USER", "alice")
	t.Setenv("E2E_AUTH_PASS", "correct-horse-battery-staple")
	extra := authConfigYAML("lab-user", loginURL, "E2E_AUTH_USER", "E2E_AUTH_PASS") + fmt.Sprintf("ports:\n  default_ports: [%s]\n", port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host, "--profile", "web", "--auth-profile", "lab-user")
	if !strings.Contains(out, "Authentication succeeded for profile \"lab-user\"") {
		t.Errorf("output missing authentication success message:\n%s", out)
	}
	if !strings.Contains(out, "Status:                 AUTHENTICATED") {
		t.Errorf("output missing authenticated status in Auth: block:\n%s", out)
	}
	if !strings.Contains(out, "\nCrawl:") {
		t.Fatalf("output missing Crawl: block entirely:\n%s", out)
	}
	if strings.Contains(out, "Authenticated URLs:      0") {
		t.Errorf("Crawl: block reports zero authenticated URLs -- the authenticated crawl did not actually happen:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/secret") {
		t.Errorf("report does not list /secret -- the authenticated-only page linked from /account was not discovered:\n%s", mdOut)
	}
}

// TestSecurity_AuthCredentials_NeverAppearInReportOrStatus is task
// section 15 adversarial scenario 23 ("secrets appearing in reports"):
// a Session is held only in memory for the process lifetime of one
// `scanner scan` invocation and is never written to the database at
// all (see docs/phase-3-14-authentication.md "Secret handling: what is
// and is not persisted") -- so `scanner report`/`scanner status`,
// which only ever read back what was persisted, have no path through
// which a credential could leak, structurally, not merely by
// convention. This test proves that empirically against the real
// commands and real output.
func TestSecurity_AuthCredentials_NeverAppearInReportOrStatus(t *testing.T) {
	srv := httptest.NewServer(e2eLoginApp("alice", "hunter2-the-e2e-secret"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_AUTH_USER", "alice")
	t.Setenv("E2E_AUTH_PASS", "hunter2-the-e2e-secret")
	extra := authConfigYAML("lab-user", loginURL, "E2E_AUTH_USER", "E2E_AUTH_PASS") + fmt.Sprintf("ports:\n  default_ports: [%s]\n", port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	scanOut := c.mustRun("scan", host, "--auth-profile", "lab-user")
	scanID := extractFullScanID(t, scanOut)

	statusOut := c.mustRun("status", scanID)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")

	for name, out := range map[string]string{"scan": scanOut, "status": statusOut, "report(markdown)": mdOut, "report(json)": jsonOut} {
		if strings.Contains(out, "hunter2-the-e2e-secret") {
			t.Fatalf("SECURITY: %s output leaked the raw password:\n%s", name, out)
		}
	}
}

func TestScanCmd_NoAuthProfile_ReportsUnauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>plain site</body></html>"))
	}))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)

	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host)
	if strings.Contains(out, "\nAuth:") {
		t.Errorf("an unauthenticated scan (no --auth-profile at all) must not print an Auth: block:\n%s", out)
	}
}
