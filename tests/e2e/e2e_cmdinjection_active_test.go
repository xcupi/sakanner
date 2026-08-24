// Phase 3.26 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> parameter discovery ->
// detection -> active mutation -> HTTP request -> execution
// correlation -> finding -> correlation -> risk -> report, against the
// REAL, already-isolated lab -- mirroring
// e2e_active_path_parameters_test.go's exact pattern (Phase 3.23).
// command-injection-active is enabled BY DEFAULT (no special flag
// needed, unlike ssrf-active/idor-active), so this file proves the
// POSITIVE case directly through the real binary, not merely
// registration.
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

func TestScanCmd_CommandInjectionActive_QueryLocation_RealBinary(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "command_injection") {
		t.Fatalf("output missing the expected command_injection finding from a real crawl-discovered query parameter:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	foundUnix, foundWindows := false, false
	for _, f := range rep.Findings {
		if f.VulnerabilityType != "command_injection" {
			continue
		}
		if f.AffectedEndpoint == "/api/ping/vulnerable" {
			foundUnix = true
		}
		if f.AffectedEndpoint == "/api/ping/vulnerable-windows" {
			foundWindows = true
		}
	}
	if !foundUnix {
		t.Errorf("report contains no command_injection finding for /api/ping/vulnerable: %+v", rep.Findings)
	}
	if !foundWindows {
		t.Errorf("report contains no command_injection finding for /api/ping/vulnerable-windows: %+v", rep.Findings)
	}
}

func TestScanCmd_CommandInjectionActive_AuthenticatedPingExec_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_CMDI_USER", lab.AccountAUsername)
	t.Setenv("E2E_CMDI_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_CMDI_USER", "E2E_CMDI_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "command_injection") {
		t.Fatalf("output missing the expected command_injection finding from the authenticated /ping-exec endpoint:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/ping-exec") {
		t.Errorf("report does not list the affected /ping-exec endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}

func TestDetectorsCmd_CommandInjectionActive_RegisteredAndEnabled(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("detectors", "list")
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "command-injection-active" {
			found = true
			if len(fields) < 2 || fields[1] != "enabled" {
				t.Errorf("command-injection-active status line = %q, want enabled (needs no external dependency, mirrors xss-reflected-active/sqli-active)", line)
			}
		}
	}
	if !found {
		t.Fatalf("detectors list is missing command-injection-active entirely:\n%s", out)
	}
}
