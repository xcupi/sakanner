// Phase 3.24 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> authenticated crawl (two
// independent identities) -> authorization (IDOR/BOLA) detection ->
// three-probe comparison -> finding -> correlation -> risk -> report,
// against the REAL, already-isolated lab (lab.StartWithAuthFixtures,
// which includes harness_authorization.go's Phase 3.24 fixtures) --
// mirroring e2e_active_path_parameters_test.go's exact pattern (Phase
// 3.23). See docs/phase-3-24-authorization.md section 17's "no
// synthetic-only proof sufficient" requirement.
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

// twoIdentityAuthzConfig mirrors authIdentityConfig
// (e2e_active_xss_test.go), extended with a SECOND identity ("account-b")
// against the SAME shared login profile -- the config shape
// --authz-identity requires.
func twoIdentityAuthzConfig(loginURL, port string) string {
	return fmt.Sprintf(`authentication:
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
      username_env: E2E_AUTHZ_A_USER
      password_env: E2E_AUTHZ_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: E2E_AUTHZ_B_USER
      password_env: E2E_AUTHZ_B_PASS
ports:
  default_ports: [%s]
`, loginURL, port)
}

func TestScanCmd_AuthzIdentity_RequiresIdentity_ExitCode5_NoScanJob(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, stderr, err := c.run("scan", "example.test", "--authz-identity", "account-b")
	if err == nil {
		t.Fatalf("expected an error for --authz-identity without --identity\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if !strings.Contains(stderr, "--identity") {
		t.Errorf("stderr does not explain --authz-identity requires --identity: %q", stderr)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite the missing --identity:\n%s", out)
	}
}

func TestScanCmd_AuthzIdentity_MustDifferFromIdentity_ExitCode5(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, stderr, err := c.run("scan", "example.test", "--identity", "account-a", "--authz-identity", "account-a")
	if err == nil {
		t.Fatalf("expected an error for --authz-identity naming the SAME identity as --identity\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if !strings.Contains(stderr, "DIFFERENT") && !strings.Contains(stderr, "different") {
		t.Errorf("stderr does not explain the identities must differ: %q", stderr)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite identical --identity/--authz-identity:\n%s", out)
	}
}

func TestScanCmd_AuthzIdentity_UnknownIdentity_ExitCode5_NoScanJob(t *testing.T) {
	configPath := writeConfig(t, "identities:\n  identities:\n    - name: account-a\n      auth_profile: lab-login\n      username_env: E2E_UNUSED_A_USER\n      password_env: E2E_UNUSED_A_PASS\nauthentication:\n  profiles:\n    - name: lab-login\n      type: form_login\n      login_url: http://127.0.0.1:1\n      username_env: E2E_UNUSED_DEFAULT_USER\n      password_env: E2E_UNUSED_DEFAULT_PASS\n")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", "example.test")

	out, _, err := c.run("scan", "example.test", "--identity", "account-a", "--authz-identity", "does-not-exist")
	if err == nil {
		t.Fatalf("expected an error for an unknown --authz-identity\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 5 {
		t.Errorf("exit code = %d, want 5 (auth failed)", code)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite the unknown --authz-identity:\n%s", out)
	}
}

// TestScanCmd_AuthorizationDetection_HorizontalFailure_RealBinary is
// this phase's own mandatory real end-to-end proof: the complete
// pipeline, through the real CLI binary, against the real lab's
// /notes?note_id= vulnerable fixture (Account A's own note, returned
// to Account B's independent session with no ownership check at all --
// lab/harness_authorization.go), while the SAME scan's /documents?doc_id=
// safe fixture (a genuine ownership check) must NOT be flagged.
func TestScanCmd_AuthorizationDetection_HorizontalFailure_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_AUTHZ_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_AUTHZ_A_PASS", lab.AccountAPassword)
	t.Setenv("E2E_AUTHZ_B_USER", lab.AccountBUsername)
	t.Setenv("E2E_AUTHZ_B_PASS", lab.AccountBPassword)
	configPath := writeConfig(t, twoIdentityAuthzConfig(loginURL, strconv.Itoa(port)))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account-a", "--authz-identity", "account-b")
	if !strings.Contains(out, "idor") {
		t.Fatalf("output missing the expected idor finding from the real /notes?note_id= horizontal-authorization-failure fixture:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}

	var foundNotesFinding, foundDocsFinding bool
	for _, f := range rep.Findings {
		if f.VulnerabilityType != "idor" {
			continue
		}
		if f.AffectedParameter == "note_id" {
			foundNotesFinding = true
			if f.IdentityContext != "account-b" {
				t.Errorf("finding IdentityContext = %q, want account-b (the acting/compare identity, not the baseline)", f.IdentityContext)
			}
		}
		if f.AffectedParameter == "doc_id" {
			foundDocsFinding = true
		}
	}
	if !foundNotesFinding {
		t.Fatalf("report contains no idor finding for the note_id parameter: %+v", rep.Findings)
	}
	if foundDocsFinding {
		t.Fatalf("report incorrectly flagged the SAFE, ownership-checked doc_id endpoint: %+v", rep.Findings)
	}

	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if strings.Contains(mdOut, lab.AccountAPassword) || strings.Contains(mdOut, lab.AccountBPassword) {
		t.Fatal("SECURITY: an account password leaked into the generated report")
	}
}

// TestScanCmd_AuthzIdentity_Omitted_IdorActiveStaysDisabled proves
// task section 6's own "omitting --authz-identity scans exactly as
// before Phase 3.24" -- idor-active must never produce a finding, and
// must not even appear as an enabled detector, when only the ordinary
// --identity flag is used.
func TestScanCmd_AuthzIdentity_Omitted_IdorActiveStaysDisabled(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_AUTHZ_A_USER", lab.AccountAUsername)
	t.Setenv("E2E_AUTHZ_A_PASS", lab.AccountAPassword)
	configPath := writeConfig(t, authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_AUTHZ_A_USER", "E2E_AUTHZ_A_PASS", lab.AccountAUsername, lab.AccountAPassword))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if strings.Contains(out, "\nidor") || strings.Contains(out, "\tidor\t") {
		t.Fatalf("an idor finding appeared despite no --authz-identity ever being supplied:\n%s", out)
	}

	listOut := c.mustRun("detectors", "list")
	for _, line := range strings.Split(listOut, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "idor-active") && strings.Contains(line, "enabled") {
			t.Errorf("idor-active shows enabled in `detectors list` despite no --authz-identity ever being supplied: %q", line)
		}
	}
}
