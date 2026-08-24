// Phase 3.32 CLI end-to-end tests: the real compiled binary, driven
// through real scans, exercising the new finding-inspection/
// reproduction capabilities and their own adversarial edge cases
// (task section SEVENTH). Inspection must remain strictly read-only.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/reporting"
	"sakanner/lab"
)

// newOperatorWorkflowCLI and scanAndCollectFindings are split out of
// realScanAndFindings so a test that needs TWO distinct scan IDs (see
// TestOperatorWorkflow_ChainMembership_NeverCrossesScans) can run two
// scans against ONE lab instance instead of starting two -- the lab's
// own cross-process setup lock (lab/harness.go's labLockAddr) is held
// for the lab's entire lifetime, released only on t.Cleanup at the end
// of the enclosing test, so starting a second lab within the same test
// function before the first is torn down deadlocks on that lock.
func newOperatorWorkflowCLI(t *testing.T, port int) *cli {
	t.Helper()
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	return newCLI(t, buildBinary(t), configPath)
}

func scanAndCollectFindings(t *testing.T, c *cli, ip string, port int) (scanID string, findings []string) {
	t.Helper()
	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	scanID = extractFullScanID(t, out)

	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v", err)
	}
	for _, f := range rep.Findings {
		findings = append(findings, f.ID)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one real finding to make this test meaningful")
	}
	return scanID, findings
}

func realScanAndFindings(t *testing.T) (c *cli, scanID string, findings []string) {
	t.Helper()
	ip, port := vulnLabCLI(t)
	c = newOperatorWorkflowCLI(t, port)
	c.mustRun("scope", "add", ip)
	scanID, findings = scanAndCollectFindings(t, c, ip, port)
	return c, scanID, findings
}

// --- 1. Out-of-scope reproduction --------------------------------------

func TestOperatorWorkflow_CurlReproduction_NeverReferencesOutOfScopeHost(t *testing.T) {
	c, _, findings := realScanAndFindings(t)
	for _, fid := range findings {
		out := c.mustRun("findings", "show", fid, "--curl")
		if strings.Contains(out, "external.scanner.test") {
			t.Errorf("SECURITY: finding %s's curl reproduction referenced the lab's own known out-of-scope host: %s", fid, out)
		}
	}
}

// --- 2/3. Secret leakage through inspection and curl output -------------

func TestOperatorWorkflow_NoRawSecretsInInspectionOrCurl(t *testing.T) {
	c, _, findings := realScanAndFindings(t)
	forbidden := []string{lab.AccountAPassword, lab.AccountBPassword}
	for _, fid := range findings {
		show := c.mustRun("findings", "show", fid)
		curl := c.mustRun("findings", "show", fid, "--curl")
		for _, secret := range forbidden {
			if strings.Contains(show, secret) {
				t.Errorf("SECURITY: findings show for %s leaked a raw password", fid)
			}
			if strings.Contains(curl, secret) {
				t.Errorf("SECURITY: curl reproduction for %s leaked a raw password", fid)
			}
		}
	}
}

// --- 4/5. Identity-context correctness / cross-identity confusion --------

func TestOperatorWorkflow_AuthenticatedFinding_ShowsCorrectIdentity(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)
	t.Setenv("E2E_OPWF_USER", lab.AccountAUsername)
	t.Setenv("E2E_OPWF_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_OPWF_USER", "E2E_OPWF_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	scanID := extractFullScanID(t, out)

	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected at least one authenticated finding")
	}
	found := false
	for _, f := range rep.Findings {
		show := c.mustRun("findings", "show", f.ID)
		if !strings.Contains(show, "Identity:") {
			t.Errorf("finding %s: show output missing an Identity: line", f.ID)
			continue
		}
		if strings.Contains(show, "Identity:    account\n") || strings.Contains(show, "Identity:    account ") {
			found = true
		}
		if strings.Contains(show, lab.AccountAPassword) {
			t.Errorf("SECURITY: finding %s show output leaked the account password", f.ID)
		}
	}
	if !found {
		t.Error("expected at least one finding to show Identity: account")
	}
}

// --- 6. Chain/finding mismatch: no cross-scan chain leakage --------------

func TestOperatorWorkflow_ChainMembership_NeverCrossesScans(t *testing.T) {
	ip, port := vulnLabCLI(t)
	c := newOperatorWorkflowCLI(t, port)
	c.mustRun("scope", "add", ip)
	scanID1, findings1 := scanAndCollectFindings(t, c, ip, port)
	scanID2, _ := scanAndCollectFindings(t, c, ip, port)
	if scanID1 == scanID2 {
		t.Fatal("test setup problem: expected two distinct scan IDs")
	}
	for _, fid := range findings1 {
		show := c.mustRun("findings", "show", fid)
		if strings.Contains(show, scanID2) {
			t.Errorf("SECURITY: finding %s's own show output references a DIFFERENT scan's ID (%s)", fid, scanID2)
		}
	}
}

// --- 5. Cross-identity finding confusion -----------------------------------

// TestOperatorWorkflow_CrossIdentityFinding_NoConfusion runs ONE real
// scan with TWO independent identities active at once (--identity
// account-a --authz-identity account-b, mirroring
// e2e_authorization_test.go's own dual-identity pattern), then proves
// every finding's own `findings show` output reports EXACTLY that
// finding's own IdentityContext -- never the OTHER identity's name --
// and never leaks either account's password, regardless of which
// identity produced the finding.
func TestOperatorWorkflow_CrossIdentityFinding_NoConfusion(t *testing.T) {
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
	scanID := extractFullScanID(t, out)

	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected at least one finding from the dual-identity scan")
	}

	checked := 0
	for _, f := range rep.Findings {
		if f.IdentityContext == "" {
			continue // unauthenticated finding, not part of this scenario
		}
		checked++
		show := c.mustRun("findings", "show", f.ID)
		wantLine := "Identity:    " + f.IdentityContext
		if !strings.Contains(show, wantLine) {
			t.Errorf("finding %s: IdentityContext=%q but show output did not contain %q:\n%s", f.ID, f.IdentityContext, wantLine, show)
		}
		other := lab.AccountBUsername
		otherPass := lab.AccountBPassword
		if f.IdentityContext == "account-b" {
			other = lab.AccountAUsername
			otherPass = lab.AccountAPassword
		}
		if strings.Contains(show, "Identity:    "+other) {
			t.Errorf("SECURITY: finding %s (identity %s) show output also references the OTHER identity %q -- cross-identity confusion", f.ID, f.IdentityContext, other)
		}
		if strings.Contains(show, lab.AccountAPassword) || strings.Contains(show, lab.AccountBPassword) || strings.Contains(show, otherPass) {
			t.Errorf("SECURITY: finding %s show output leaked a raw password", f.ID)
		}
	}
	if checked == 0 {
		t.Fatal("expected at least one finding with a non-empty IdentityContext to make this test meaningful")
	}
}

// --- 7. Malformed finding IDs ---------------------------------------------

func TestOperatorWorkflow_MalformedFindingID_CleanError(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	for _, badID := range []string{
		"not-a-real-id",
		"' OR '1'='1",
		"../../etc/passwd",
		"",
		strings.Repeat("a", 10000),
	} {
		args := []string{"findings", "show"}
		if badID != "" {
			args = append(args, badID)
		} else {
			continue // ExactArgs(1) rejects a missing arg at the cobra level; covered separately
		}
		_, stderr, err := c.run(args...)
		if err == nil {
			t.Errorf("expected an error for malformed finding ID %q", badID)
		}
		if strings.Contains(stderr, "panic") {
			t.Errorf("SECURITY: malformed finding ID %q caused a panic:\n%s", badID, stderr)
		}
	}
}

// --- 8. Malicious endpoint/parameter-shaped values as CLI arguments ------

func TestOperatorWorkflow_MaliciousCLIArgument_NeverExecutedOrInjected(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	malicious := []string{
		"$(whoami)",
		"`whoami`",
		"; rm -rf /",
		"' OR '1'='1' --",
	}
	for _, m := range malicious {
		_, stderr, err := c.run("findings", "show", m)
		if err == nil {
			t.Errorf("expected an error (not found) for malicious-shaped finding ID %q", m)
		}
		if strings.Contains(stderr, "panic") {
			t.Errorf("SECURITY: malicious CLI argument %q caused a panic:\n%s", m, stderr)
		}
	}
}

// --- 11. Path traversal through exported evidence --------------------------

// TestOperatorWorkflow_NoEvidenceExportCapability_PathTraversalNotApplicable
// establishes, with real CLI evidence, that this adversarial scenario
// does not apply to sakanner today: `findings`/`findings show`/`chains`/
// `chains show` -- the ONLY commands that display finding/chain
// evidence -- accept no output-path flag of any kind and never write a
// file. The one command in the whole binary that writes a file is
// `report --output <path>`, and that path comes ONLY from the
// operator's own CLI argument, never from any finding/chain-derived
// (i.e. target-controlled) string -- proven here by writing a report
// to an operator-chosen path and confirming the file lands at exactly
// that path with no finding data able to influence it.
func TestOperatorWorkflow_NoEvidenceExportCapability_PathTraversalNotApplicable(t *testing.T) {
	c, scanID, findings := realScanAndFindings(t)

	for _, args := range [][]string{
		{"findings", "show", findings[0], "--output", "/tmp/should-not-exist"},
		{"findings", "show", findings[0], "--export", "/tmp/should-not-exist"},
		{"chains", "--scan", scanID, "--output", "/tmp/should-not-exist"},
	} {
		_, stderr, err := c.run(args...)
		if err == nil {
			t.Errorf("expected %v to be rejected (no such flag exists) -- if this now succeeds, evidence export has been added and this scenario needs real path-traversal testing", args)
		}
		if !strings.Contains(stderr, "unknown flag") {
			t.Errorf("expected an 'unknown flag' rejection for %v, got: %s", args, stderr)
		}
	}

	outPath := filepath.Join(t.TempDir(), "report.json")
	c.mustRun("report", "--scan", scanID, "--format", "json", "--output", outPath)
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected report --output to write exactly the operator-given path: %v", err)
	}
}

// --- 12. Inspection remains read-only: --curl never mutates state --------

func TestOperatorWorkflow_CurlFlag_NeverMutatesFindingsOrChains(t *testing.T) {
	c, scanID, findings := realScanAndFindings(t)
	before := c.mustRun("findings", "--scan", scanID)
	for _, fid := range findings {
		c.mustRun("findings", "show", fid, "--curl")
	}
	after := c.mustRun("findings", "--scan", scanID)
	if before != after {
		t.Errorf("SECURITY: `findings show --curl` changed the findings list output -- inspection must be strictly read-only\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
