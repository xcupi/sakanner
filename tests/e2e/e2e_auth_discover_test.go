// Phase 3.36 CLI end-to-end tests: automatic login-form discovery
// (TypeFormLoginAuto / "scanner auth discover"), driven through the
// real compiled binary against the existing, generic (not
// DVWA-specific) lab auth fixture -- lab/harness_auth.go's own
// conventional username/password form at /login, already used by
// every existing form_login e2e test. These tests deliberately give
// sakanner ONLY a start_url, never login_url/username_field/
// password_field, proving discovery -- not operator configuration --
// finds the real login page/form/fields.
package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"sakanner/lab"
)

// autoDiscoverIdentityConfig mirrors authIdentityConfig's exact shape
// (e2e_active_xss_test.go) but for a TypeFormLoginAuto profile:
// start_url instead of login_url, and no username_field/password_field
// at all.
func autoDiscoverIdentityConfig(startURL, port, userEnv, passEnv string) string {
	return fmt.Sprintf(`authentication:
  profiles:
    - name: auto-login
      type: form_login_auto
      start_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: auto-account
      auth_profile: auto-login
      username_env: %s
      password_env: %s
ports:
  default_ports: [%s]
`, startURL, userEnv, passEnv, port)
}

func TestAuthDiscover_PreviewCommand_FindsRealLoginForm(t *testing.T) {
	ip, port := authLabCLI(t)
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)
	out := c.mustRun("auth", "discover", loginURL)
	if !strings.Contains(out, "Login form discovered:") {
		t.Fatalf("expected a discovered-form report, got:\n%s", out)
	}
	if !strings.Contains(out, "Username field: username") || !strings.Contains(out, "Password field: password") {
		t.Errorf("expected the real form's own field names to be reported, got:\n%s", out)
	}
}

func TestAuthDiscover_PreviewCommand_NeverMutatesOrAuthenticates(t *testing.T) {
	ip, port := authLabCLI(t)
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	out := c.mustRun("auth", "discover", loginURL)
	if strings.Contains(out, "Authentication succeeded") {
		t.Errorf("a credential-free preview must never authenticate, got:\n%s", out)
	}
}

func TestAuthDiscover_WithCredentials_ActuallyAuthenticates(t *testing.T) {
	ip, port := authLabCLI(t)
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_AUTODISC_USER", lab.AccountAUsername)
	t.Setenv("E2E_AUTODISC_PASS", lab.AccountAPassword)
	out := c.mustRun("auth", "discover", loginURL, "--username-env", "E2E_AUTODISC_USER", "--password-env", "E2E_AUTODISC_PASS")
	if !strings.Contains(out, "Authentication succeeded") {
		t.Fatalf("expected discovery+authentication to succeed with real lab credentials, got:\n%s", out)
	}
	if strings.Contains(out, lab.AccountAPassword) {
		t.Error("SECURITY: the real password leaked into command output")
	}
}

func TestAuthDiscover_WrongCredentials_FailsCleanly(t *testing.T) {
	ip, port := authLabCLI(t)
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_AUTODISC_BADUSER", "not-a-real-user")
	t.Setenv("E2E_AUTODISC_BADPASS", "not-a-real-password")
	_, stderr, err := c.run("auth", "discover", loginURL, "--username-env", "E2E_AUTODISC_BADUSER", "--password-env", "E2E_AUTODISC_BADPASS")
	if err == nil {
		t.Fatal("expected a non-zero exit for a failed login")
	}
	if strings.Contains(stderr, "panic") {
		t.Fatalf("SECURITY: a failed login attempt caused a panic:\n%s", stderr)
	}
}

func TestAuthDiscover_MissingArgument_ClearError(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	_, stderr, err := c.run("auth", "discover")
	if err == nil {
		t.Fatal("expected an error for a missing start URL")
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected a Usage: block in the error, got:\n%s", stderr)
	}
}

func TestAuthDiscover_InvalidURL_ClearError(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	_, stderr, err := c.run("auth", "discover", "not-a-valid-url")
	if err == nil {
		t.Fatal("expected an error for an invalid start URL")
	}
	if strings.Contains(stderr, "panic") {
		t.Fatalf("SECURITY: an invalid URL argument caused a panic:\n%s", stderr)
	}
}

func TestAuthDiscover_OnlyOneOfUsernamePasswordEnv_ClearError(t *testing.T) {
	ip, port := authLabCLI(t)
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	_, stderr, err := c.run("auth", "discover", loginURL, "--username-env", "SOME_VAR")
	if err == nil {
		t.Fatal("expected an error when only --username-env is given")
	}
	if !strings.Contains(stderr, "--username-env and --password-env") {
		t.Errorf("expected a clear error naming both flags, got:\n%s", stderr)
	}
}

// TestScanCmd_FormLoginAuto_IdentityAuthenticates_RealBinary proves the
// FULL workflow: a config with ONLY start_url (no login_url/
// username_field/password_field at all) still produces a successful
// authenticated scan via --identity, exactly like an explicit
// form_login profile would -- the real end-to-end proof that
// TypeFormLoginAuto is a genuine drop-in alternative, not merely a
// standalone preview command.
func TestScanCmd_FormLoginAuto_IdentityAuthenticates_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)
	t.Setenv("E2E_AUTODISC_SCAN_USER", lab.AccountAUsername)
	t.Setenv("E2E_AUTODISC_SCAN_PASS", lab.AccountAPassword)
	extra := autoDiscoverIdentityConfig(loginURL, strconv.Itoa(port), "E2E_AUTODISC_SCAN_USER", "E2E_AUTODISC_SCAN_PASS")
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "recon", "--identity", "auto-account")
	if !strings.Contains(out, "Status:") {
		t.Fatalf("expected a normal scan status line, got:\n%s", out)
	}
	if strings.Contains(out, lab.AccountAPassword) {
		t.Error("SECURITY: the real password leaked into scan output")
	}
}

func TestScanCmd_FormLoginAuto_WrongCredentials_ExitAuthFailed(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)
	t.Setenv("E2E_AUTODISC_BAD_SCAN_USER", "wrong-user")
	t.Setenv("E2E_AUTODISC_BAD_SCAN_PASS", "wrong-pass")
	extra := autoDiscoverIdentityConfig(loginURL, strconv.Itoa(port), "E2E_AUTODISC_BAD_SCAN_USER", "E2E_AUTODISC_BAD_SCAN_PASS")
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	_, stderr, err := c.run("scan", ip, "--profile", "recon", "--identity", "auto-account")
	if err == nil {
		t.Fatal("expected the scan command to fail for wrong credentials")
	}
	if strings.Contains(stderr, "panic") {
		t.Fatalf("SECURITY: wrong credentials caused a panic:\n%s", stderr)
	}
}
