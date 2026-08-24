// Phase 3.19 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> parameter discovery ->
// detection -> active mutation -> HTTP request -> response comparison
// -> finding -> correlation -> risk -> report, against the REAL,
// already-isolated lab (imported from sakanner/lab, the same
// established pattern e2e_detection_readiness_test.go already uses --
// see that file's own doc comment for why this is the one place in
// the repository allowed to import it).
package e2e

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"sakanner/lab"
)

// authLabCLI starts the real, isolated auth+vuln lab
// (lab.StartWithAuthFixtures, which includes harness_auth.go's Phase
// 3.19 /search fixture) and returns its bare, real, dialable IP/port --
// exactly vulnLabCLI's own reasoning: the CLI runs as a real
// subprocess using the real system resolver, which cannot see the
// in-process dns.FakeResolver's "auth.scanner.test" mapping, so the
// literal 127.0.0.26 address is used directly instead.
func authLabCLI(t *testing.T) (ip string, port int) {
	t.Helper()
	gt, err := lab.LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	l, err := lab.StartWithAuthFixtures(gt)
	if err != nil {
		t.Fatalf("StartWithAuthFixtures: %v", err)
	}
	t.Cleanup(l.Close)

	host, portStr, err := net.SplitHostPort(l.AuthAddr)
	if err != nil {
		t.Fatalf("split lab addr %q: %v", l.AuthAddr, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

func authIdentityConfig(loginURL, port string, userEnv, passEnv, username, password string) string {
	return fmt.Sprintf(`authentication:
  profiles:
    - name: lab-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account
      auth_profile: lab-login
      username_env: %s
      password_env: %s
ports:
  default_ports: [%s]
`, loginURL, userEnv, passEnv, port)
}

func TestScanCmd_ActiveXSS_AuthenticatedPositive_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_XSS_USER", lab.AccountAUsername)
	t.Setenv("E2E_XSS_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_XSS_USER", "E2E_XSS_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "reflected_xss") {
		t.Fatalf("output missing the expected reflected_xss finding from the authenticated /search endpoint:\n%s", out)
	}
	if !strings.Contains(out, "Requests issued:") {
		t.Errorf("output missing the new 'Requests issued:' observability line:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/search") {
		t.Errorf("report does not list the affected /search endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}

func TestScanCmd_ActiveXSS_IdentityAAndB_IndependentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_XSS_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_XSS_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_XSS_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_XSS_B_PASS", lab.AccountBPassword)
	extra := fmt.Sprintf(`authentication:
  profiles:
    - name: lab-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account-a
      auth_profile: lab-login
      username_env: E2E_XSS_A_USER
      password_env: E2E_XSS_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_XSS_B_USER
      password_env: E2E_XSS_B_PASS
ports:
  default_ports: [%d]
`, loginURL, port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	outA := c.mustRun("scan", ip, "--profile", "web", "--identity", "account-a")
	outB := c.mustRun("scan", ip, "--profile", "web", "--identity", "account-b")

	for name, out := range map[string]string{"account-a": outA, "account-b": outB} {
		if !strings.Contains(out, "reflected_xss") {
			t.Errorf("%s: output missing the expected reflected_xss finding:\n%s", name, out)
		}
	}
	if strings.Contains(outA, lab.AccountBPassword) || strings.Contains(outB, lab.AccountAPassword) {
		t.Fatal("SECURITY: one identity's scan output contains the OTHER identity's password")
	}
}

func TestScanCmd_ActiveXSS_ConcurrentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_XSS_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_XSS_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_XSS_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_XSS_B_PASS", lab.AccountBPassword)
	extra := fmt.Sprintf(`authentication:
  profiles:
    - name: lab-login
      type: form_login
      login_url: %s
      username_env: E2E_UNUSED_DEFAULT_USER
      password_env: E2E_UNUSED_DEFAULT_PASS
identities:
  identities:
    - name: account-a
      auth_profile: lab-login
      username_env: E2E_XSS_A_USER
      password_env: E2E_XSS_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_XSS_B_USER
      password_env: E2E_XSS_B_PASS
ports:
  default_ports: [%d]
`, loginURL, port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	var wg sync.WaitGroup
	outs := make([]string, 2)
	identities := []string{"account-a", "account-b"}
	for i, identity := range identities {
		wg.Add(1)
		go func(i int, identity string) {
			defer wg.Done()
			outs[i] = c.mustRun("scan", ip, "--profile", "web", "--identity", identity)
		}(i, identity)
	}
	wg.Wait()

	for i, out := range outs {
		if !strings.Contains(out, "Status:   COMPLETED") {
			t.Errorf("scan %d (%s): output missing a COMPLETED status:\n%s", i, identities[i], out)
		}
		if !strings.Contains(out, "reflected_xss") {
			t.Errorf("scan %d (%s): output missing the expected reflected_xss finding:\n%s", i, identities[i], out)
		}
	}
}
