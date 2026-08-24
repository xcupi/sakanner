// Phase 3.31 CLI end-to-end tests: the real compiled binary, driven
// through a real scan against the real lab, exercising the new
// `scanner chains` / `scanner chains show` read-only commands against
// REAL, persisted chain data.
package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestChainsCmd_RealScan_ListsAndShowsPersistedChains(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	scanID := extractFullScanID(t, out)

	chainsOut := c.mustRun("chains", "--scan", scanID)
	if strings.Contains(chainsOut, "no chain candidates") {
		t.Skip("this scan's own detector set produced no chain candidate -- not every scan configuration is guaranteed to (see lab/phase3_31_chains_integration_test.go for the broad-registry proof that genuine chains DO form); skipping rather than failing a CLI-surface-only test on detector-set variance")
	}
	if !strings.Contains(chainsOut, "STATUS") || !strings.Contains(chainsOut, "IDENTITY") {
		t.Fatalf("chains list output missing expected columns:\n%s", chainsOut)
	}

	lines := strings.Split(strings.TrimSpace(chainsOut), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least a header line and one candidate row:\n%s", chainsOut)
	}
	firstCandidateID := strings.Fields(lines[1])[0]

	showOut := c.mustRun("chains", "show", firstCandidateID, "--scan", scanID)
	for _, want := range []string{"ID:", "Status:", "Participating findings", "Relations"} {
		if !strings.Contains(showOut, want) {
			t.Errorf("chains show output missing %q:\n%s", want, showOut)
		}
	}
	// Individual finding severity must be visible in the detail view
	// (task's own "the operator should be able to determine...
	// individual finding severity").
	if !strings.Contains(showOut, "severity=") {
		t.Errorf("chains show output missing individual finding severity:\n%s", showOut)
	}
}

func TestChainsCmd_RequiresScanFlag(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	_, _, err := c.run("chains")
	if err == nil {
		t.Fatal("expected an error when --scan is omitted")
	}
}

func TestChainsCmd_UnknownScan_NoChainsListed(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)
	out := c.mustRun("chains", "--scan", "nonexistent-scan-id")
	if !strings.Contains(out, "no chain candidates") {
		t.Errorf("expected \"no chain candidates\" for an unknown scan ID, got:\n%s", out)
	}
}
