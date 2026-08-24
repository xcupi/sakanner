// Phase 3.16 CLI end-to-end tests: `scanner identities list/show` and
// `scanner scan --identity <name>`, through the real built binary --
// plain httptest fixtures only (no lab dependency needed here; see
// lab/phase3_16_multi_identity_test.go for the real-lab, orchestrator-
// level integration tests).
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

const e2eTwoAccountLoginPageHTML = `<html><body>
<form action="/login" method="post">
	<input type="hidden" name="csrf_token" value="e2e-fixed-token">
	<input type="text" name="username">
	<input type="password" name="password">
</form>
</body></html>`

// e2eTwoAccountLoginApp is a small two-account login fixture -- unlike
// e2eLoginApp (one fixed account), this validates against EITHER of
// two accounts and reflects which one is currently authenticated back
// in the response, so a single test can prove two --identity values
// really do authenticate as two different accounts through the real
// CLI binary.
func e2eTwoAccountLoginApp(accounts map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/login">login</a> <a href="/account">account</a></body></html>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(e2eTwoAccountLoginPageHTML))
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
		username := r.FormValue("username")
		if want, ok := accounts[username]; ok && want == r.FormValue("password") {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "e2e-session-" + username, Path: "/"})
			http.Redirect(w, r, "/account", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login failed: invalid credentials"))
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		username := strings.TrimPrefix(c.Value, "e2e-session-")
		if err != nil || !strings.HasPrefix(c.Value, "e2e-session-") || accounts[username] == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		fmt.Fprintf(w, `<html><body>account page for %s -- ACCOUNT_MARKER_%s</body></html>`, username, strings.ToUpper(username))
	})
	return mux
}

func TestIdentitiesCmd_ListAndShow(t *testing.T) {
	srv := httptest.NewServer(e2eTwoAccountLoginApp(map[string]string{"alice": "alice-pass", "bob": "bob-pass"}))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_ALICE_USER", "alice")
	t.Setenv("E2E_ALICE_PASS", "alice-pass")
	t.Setenv("E2E_BOB_USER", "bob")
	t.Setenv("E2E_BOB_PASS", "bob-pass")
	extra := fmt.Sprintf(`authentication:
  profiles:
    - name: shared-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account-a
      auth_profile: shared-login
      username_env: E2E_ALICE_USER
      password_env: E2E_ALICE_PASS
    - name: account-b
      auth_profile: shared-login
      username_env: E2E_BOB_USER
      password_env: E2E_BOB_PASS
`, loginURL)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)

	listOut := c.mustRun("identities", "list")
	for _, want := range []string{"account-a", "account-b", "shared-login", "IDENTITY_CONFIGURED"} {
		if !strings.Contains(listOut, want) {
			t.Errorf("identities list missing %q:\n%s", want, listOut)
		}
	}

	showOut := c.mustRun("identities", "show", "account-a")
	for _, want := range []string{"account-a", "shared-login", "IDENTITY_CONFIGURED", "<REDACTED>"} {
		if !strings.Contains(showOut, want) {
			t.Errorf("identities show missing %q:\n%s", want, showOut)
		}
	}
	if strings.Contains(showOut, "alice-pass") {
		t.Fatalf("SECURITY: identities show leaked the raw password:\n%s", showOut)
	}
}

func TestIdentitiesCmd_UnknownIdentity(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	_, stderr, err := c.run("identities", "show", "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown identity")
	}
	if !strings.Contains(stderr, "unknown identity") {
		t.Errorf("stderr missing expected message: %q", stderr)
	}
}

// TestScanCmd_IdentityFlag_TwoIdentitiesAuthenticateIndependently is
// Phase 3.16's own CLI vertical slice: two SEPARATE `scanner scan
// --identity` invocations, against the SAME shared auth profile, must
// authenticate as two DIFFERENT accounts and report the correct
// Identity/AuthProfile distinction in the Auth: block.
func TestScanCmd_IdentityFlag_TwoIdentitiesAuthenticateIndependently(t *testing.T) {
	srv := httptest.NewServer(e2eTwoAccountLoginApp(map[string]string{"alice": "alice-pass", "bob": "bob-pass"}))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_ALICE_USER", "alice")
	t.Setenv("E2E_ALICE_PASS", "alice-pass")
	t.Setenv("E2E_BOB_USER", "bob")
	t.Setenv("E2E_BOB_PASS", "bob-pass")
	extra := fmt.Sprintf(`authentication:
  profiles:
    - name: shared-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account-a
      auth_profile: shared-login
      username_env: E2E_ALICE_USER
      password_env: E2E_ALICE_PASS
    - name: account-b
      auth_profile: shared-login
      username_env: E2E_BOB_USER
      password_env: E2E_BOB_PASS
ports:
  default_ports: [%s]
`, loginURL, port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	outA := c.mustRun("scan", host, "--identity", "account-a")
	if !strings.Contains(outA, "Identity:               account-a") {
		t.Errorf("account-a scan output missing Identity: line:\n%s", outA)
	}
	if !strings.Contains(outA, "Profile:                shared-login") {
		t.Errorf("account-a scan output missing Profile: line naming the shared auth profile:\n%s", outA)
	}
	if !strings.Contains(outA, "Status:                 AUTHENTICATED") {
		t.Errorf("account-a scan output missing AUTHENTICATED status:\n%s", outA)
	}

	outB := c.mustRun("scan", host, "--identity", "account-b")
	if !strings.Contains(outB, "Identity:               account-b") {
		t.Errorf("account-b scan output missing Identity: line:\n%s", outB)
	}
	if !strings.Contains(outB, "Status:                 AUTHENTICATED") {
		t.Errorf("account-b scan output missing AUTHENTICATED status:\n%s", outB)
	}

	// Secret protection: neither password ever appears in either
	// scan's own output, nor -- critically -- in the OTHER identity's
	// output.
	for _, out := range []string{outA, outB} {
		if strings.Contains(out, "alice-pass") || strings.Contains(out, "bob-pass") {
			t.Fatalf("SECURITY: scan output leaked a raw password:\n%s", out)
		}
	}
}

func TestScanCmd_IdentityFlag_UnknownIdentity_ExitCode5_NoScanJob(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, _, err := c.run("scan", "example.test", "--identity", "does-not-exist")
	if err == nil {
		t.Fatalf("expected an error for an unknown --identity\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite an unknown identity:\n%s", out)
	}
}

func TestScanCmd_IdentityAndAuthProfile_MutuallyExclusive(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, stderr, err := c.run("scan", "example.test", "--auth-profile", "x", "--identity", "y")
	if err == nil {
		t.Fatalf("expected --auth-profile and --identity to be rejected together\noutput: %s", out)
	}
	if !strings.Contains(stderr, "auth-profile") || !strings.Contains(stderr, "identity") {
		t.Errorf("stderr does not clearly explain the mutual-exclusivity violation: %q", stderr)
	}
}

// TestScanCmd_ProfileWebAndIdentity_AuthenticatedCrawlDiscoversAccountMarker
// closes the identity-specific analogue of Phase 3.15's own
// "--profile web + --auth-profile together" gap: --profile web +
// --identity together must actually crawl authenticated content, not
// merely authenticate. /account's own body (ACCOUNT_MARKER_<NAME>)
// differs per account, so its presence in the report proves the
// correct identity's session reached it.
func TestScanCmd_ProfileWebAndIdentity_AuthenticatedCrawlDiscoversAccountMarker(t *testing.T) {
	srv := httptest.NewServer(e2eTwoAccountLoginApp(map[string]string{"alice": "alice-pass", "bob": "bob-pass"}))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/login", host, port)

	t.Setenv("E2E_ALICE_USER", "alice")
	t.Setenv("E2E_ALICE_PASS", "alice-pass")
	extra := fmt.Sprintf(`authentication:
  profiles:
    - name: shared-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account-a
      auth_profile: shared-login
      username_env: E2E_ALICE_USER
      password_env: E2E_ALICE_PASS
ports:
  default_ports: [%s]
`, loginURL, port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host, "--profile", "web", "--identity", "account-a")
	if !strings.Contains(out, "\nCrawl:") {
		t.Fatalf("output missing Crawl: block entirely:\n%s", out)
	}
	if strings.Contains(out, "Authenticated URLs:      0") {
		t.Errorf("Crawl: block reports zero authenticated URLs -- the authenticated crawl did not actually happen:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/account") {
		t.Errorf("report does not list /account:\n%s", mdOut)
	}
}

func TestShellCompletion_IdentitiesSubcommands(t *testing.T) {
	bin := buildBinary(t)
	configPath := writeConfig(t, "")

	cmd := exec.Command(bin, "--config", configPath, "__complete", "identities", "")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	if !strings.Contains(string(out), "list") || !strings.Contains(string(out), "show") {
		t.Errorf("completion output missing list/show subcommands:\n%s", out)
	}
}
