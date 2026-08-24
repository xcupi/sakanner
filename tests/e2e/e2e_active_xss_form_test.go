// Phase 3.22 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> FORM discovery -> detection
// -> active FORM mutation -> HTTP request -> response comparison ->
// finding -> correlation -> risk -> report, proving xssactive's new
// form-location coverage (task section 3) through the REAL binary --
// mirroring e2e_active_form_mutation_test.go's exact pattern (Phase
// 3.21, for sqliactive) for xssactive instead. XSS-via-query and
// XSS-via-JSON e2e coverage already exist (e2e_active_xss_test.go,
// Phase 3.19; XSS-via-JSON is proven at the lab level only, since the
// crawler cannot discover a live JSON request body -- an unchanged,
// already-documented boundary, not something this phase's own e2e
// suite can close). This file's own tests are what close the
// remaining XSS-via-form gap specifically.
package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"sakanner/lab"
)

func TestScanCmd_ActiveXSSForm_RealBinary(t *testing.T) {
	ip, port := vulnLabCLI(t)
	// See e2e_active_form_mutation_test.go's own doc comment for why
	// crawler.max_pages must be raised and --profile omitted here.
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "reflected_xss") {
		t.Fatalf("output missing the expected reflected_xss finding from the real <form method=POST> on /forms/index:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/xss/reflected/form-vulnerable") {
		t.Errorf("report does not list the affected /xss/reflected/form-vulnerable endpoint:\n%s", mdOut)
	}
}

func TestScanCmd_ActiveXSSForm_AuthenticatedPOSTForm_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_XSSFORM_USER", lab.AccountAUsername)
	t.Setenv("E2E_XSSFORM_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_XSSFORM_USER", "E2E_XSSFORM_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "reflected_xss") {
		t.Fatalf("output missing the expected reflected_xss finding from the authenticated /search-form POST form:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/search-form") {
		t.Errorf("report does not list the affected /search-form endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}

func TestScanCmd_ActiveXSSForm_IdentityAAndB_IndependentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_XSSFORM_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_XSSFORM_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_XSSFORM_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_XSSFORM_B_PASS", lab.AccountBPassword)
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
      username_env: E2E_XSSFORM_A_USER
      password_env: E2E_XSSFORM_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_XSSFORM_B_USER
      password_env: E2E_XSSFORM_B_PASS
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
	if strings.Contains(outs[0], lab.AccountBPassword) || strings.Contains(outs[1], lab.AccountAPassword) {
		t.Fatal("SECURITY: one identity's scan output contains the OTHER identity's password")
	}
}
