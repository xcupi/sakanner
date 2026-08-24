// Phase 3.21 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> FORM discovery -> detection
// -> active FORM mutation -> HTTP request -> response comparison ->
// finding -> correlation -> risk -> report, against the REAL,
// already-isolated lab -- mirroring e2e_active_sqli_test.go's exact
// pattern (Phase 3.20) for the new form-location adapter instead.
//
// The two vuln-lab tests below raise crawler.max_pages/max_depth via
// config and deliberately omit --profile, routing through
// internal/policy's config-driven "legacy" path (resolve.go:85-86) --
// "--profile web" hardcodes its own depth=2/pages=20
// (resolve.go:77-82) and would ignore this file's config entirely.
// The vuln lab's own index page has grown to 40+ links across every
// prior phase's own fixtures, and /forms/index (this phase's own
// link) is appended at the very end of that list, so the default
// budget is not enough to guarantee reaching it within one crawl --
// exactly the same reasoning lab/phase3_21_form_mutation_test.go's own
// formMutationOrchestrator documents. The auth-lab tests don't need
// this: /lookup-form is directly linked from /dashboard at shallow
// depth, well within --profile web's own default budget.
package e2e

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/reporting"
	"sakanner/lab"
)

func TestScanCmd_ActiveFormMutation_POSTForm_RealBinary(t *testing.T) {
	ip, port := vulnLabCLI(t)
	// "--profile web" would ignore this config's own crawler.max_pages
	// (the profile registry hardcodes web's own depth=2/pages=20,
	// internal/policy/resolve.go:77-82) -- omitting --profile entirely
	// routes through the config-driven "legacy" policy instead
	// (internal/policy/resolve.go:85-86), which DOES honor
	// crawler.max_pages/max_depth from this file.
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from the real <form method=POST> on /forms/index:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	found := false
	for _, f := range rep.Findings {
		if f.VulnerabilityType == "sql_injection" && f.AffectedEndpoint == "/sqli/form/vulnerable" {
			found = true
			if f.AffectedParameter != "id" {
				t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
			}
		}
	}
	if !found {
		t.Fatalf("report contains no sql_injection finding for /sqli/form/vulnerable: %+v", rep.Findings)
	}
}

func TestScanCmd_ActiveFormMutation_OutOfScopeAction_NeverBecomesFinding(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")

	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	for _, f := range rep.Findings {
		if f.AffectedParameter == "secret" {
			t.Fatalf("SECURITY: the out-of-scope form's 'secret' field produced a finding: %+v", f)
		}
	}
	// The out-of-scope form's own endpoint must still be visible in the
	// report's Endpoints (discovery is not the same as authorization to
	// mutate) -- confirms this is a deliberate exclusion, not discovery
	// itself silently failing.
	foundEndpoint := false
	for _, e := range rep.Endpoints {
		if e.Source == "form" && e.ActionOrigin == "http://external.scanner.test:80" {
			foundEndpoint = true
		}
	}
	if !foundEndpoint {
		t.Fatal("the out-of-scope form's own endpoint/ActionOrigin was not recorded in the report at all")
	}
}

func TestScanCmd_ActiveFormMutation_AuthenticatedPOSTForm_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_FORM_USER", lab.AccountAUsername)
	t.Setenv("E2E_FORM_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_FORM_USER", "E2E_FORM_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from the authenticated /lookup-form POST form:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/lookup-form") {
		t.Errorf("report does not list the affected /lookup-form endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}

func TestScanCmd_ActiveFormMutation_IdentityAAndB_IndependentScans_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_FORM_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_FORM_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_FORM_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_FORM_B_PASS", lab.AccountBPassword)
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
      username_env: E2E_FORM_A_USER
      password_env: E2E_FORM_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_FORM_B_USER
      password_env: E2E_FORM_B_PASS
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
