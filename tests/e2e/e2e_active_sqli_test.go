// Phase 3.20 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> parameter discovery ->
// detection -> active mutation -> HTTP request -> response comparison
// -> finding -> correlation -> risk -> report, against the REAL,
// already-isolated lab -- mirroring e2e_active_xss_test.go's exact
// pattern (Phase 3.19) for the sqli-active detector instead.
package e2e

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"sakanner/internal/reporting"
	"sakanner/lab"
)

func TestScanCmd_ActiveSQLi_UnauthenticatedPositive_RealBinary(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from /sqli/vulnerable:\n%s", out)
	}
	if !strings.Contains(out, "Requests issued:") {
		t.Errorf("output missing the 'Requests issued:' observability line:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/sqli/vulnerable") {
		t.Errorf("report does not list the affected /sqli/vulnerable endpoint:\n%s", mdOut)
	}
}

func TestScanCmd_ActiveSQLi_Benign_RealBinary_NoFinding(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	// The same crawl also reaches /sqli/vulnerable and
	// /sqli/boolean/vulnerable, which legitimately DO produce
	// sql_injection findings -- so this test parses the structured JSON
	// report (rather than substring-matching the markdown one) to
	// assert precisely WHICH endpoints a sql_injection finding is
	// attached to, not merely whether the words appear anywhere in the
	// output. /sqli/safe, /sqli/boolean/safe, /sqli/generic-error, and
	// /sqli/dynamic must never appear as an AffectedEndpoint on any
	// sql_injection finding (see docs/phase-3-20-sqli.md section 1
	// point 8 for what each false-positive trap defends against).
	out := c.mustRun("scan", ip, "--profile", "web", "--ports", strconv.Itoa(port))
	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")

	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	benign := map[string]bool{"/sqli/safe": true, "/sqli/boolean/safe": true, "/sqli/generic-error": true, "/sqli/dynamic": true}
	for _, f := range rep.Findings {
		if f.VulnerabilityType == "sql_injection" && benign[f.AffectedEndpoint] {
			t.Errorf("SECURITY: benign/false-positive-trap endpoint %s produced a sql_injection finding: %+v", f.AffectedEndpoint, f)
		}
	}
}

func TestScanCmd_ActiveSQLi_AuthenticatedPositive_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_SQLI_USER", lab.AccountAUsername)
	t.Setenv("E2E_SQLI_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_SQLI_USER", "E2E_SQLI_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from the authenticated /lookup endpoint:\n%s", out)
	}
	if !strings.Contains(out, "Requests issued:") {
		t.Errorf("output missing the 'Requests issued:' observability line:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/lookup") {
		t.Errorf("report does not list the affected /lookup endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}

func TestScanCmd_ActiveSQLi_IdentityAAndB_IndependentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_SQLI_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_SQLI_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_SQLI_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_SQLI_B_PASS", lab.AccountBPassword)
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
      username_env: E2E_SQLI_A_USER
      password_env: E2E_SQLI_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_SQLI_B_USER
      password_env: E2E_SQLI_B_PASS
ports:
  default_ports: [%d]
`, loginURL, port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	outA := c.mustRun("scan", ip, "--profile", "web", "--identity", "account-a")
	outB := c.mustRun("scan", ip, "--profile", "web", "--identity", "account-b")

	for name, out := range map[string]string{"account-a": outA, "account-b": outB} {
		if !strings.Contains(out, "sql_injection") {
			t.Errorf("%s: output missing the expected sql_injection finding:\n%s", name, out)
		}
	}
	if strings.Contains(outA, lab.AccountBPassword) || strings.Contains(outB, lab.AccountAPassword) {
		t.Fatal("SECURITY: one identity's scan output contains the OTHER identity's password")
	}
}

func TestScanCmd_ActiveSQLi_ConcurrentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_SQLI_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_SQLI_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_SQLI_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_SQLI_B_PASS", lab.AccountBPassword)
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
      username_env: E2E_SQLI_A_USER
      password_env: E2E_SQLI_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_SQLI_B_USER
      password_env: E2E_SQLI_B_PASS
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
		if !strings.Contains(out, "sql_injection") {
			t.Errorf("scan %d (%s): output missing the expected sql_injection finding:\n%s", i, identities[i], out)
		}
	}
}
