// Phase 3.23 CLI end-to-end tests: the real built binary, driven
// through scope -> discovery -> crawler -> path-parameter discovery ->
// detection -> active path mutation -> HTTP request -> response
// comparison -> finding -> correlation -> risk -> report, proving
// path-location coverage (task section 13's own explicit "at least
// one complete test must exercise real crawl -> ... -> finding ->
// evidence -> correlation/risk") through the REAL binary -- mirroring
// e2e_active_form_mutation_test.go's exact pattern (Phase 3.21).
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

func TestScanCmd_ActivePathParameter_SQLiViaNumericSegment_RealBinary(t *testing.T) {
	ip, port := vulnLabCLI(t)
	// See e2e_active_form_mutation_test.go's own doc comment for why
	// crawler.max_pages must be raised and --profile omitted here.
	configPath := writeConfig(t, fmt.Sprintf("crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from a real crawl-discovered numeric path segment:\n%s", out)
	}

	scanID := extractFullScanID(t, out)

	// scanner inputs --location path (task section 11): the discovered
	// path parameter must be visible via the general-purpose inputs
	// command, with zero new CLI code (docs/phase-3-23-path-parameters.md
	// section 11).
	inputsOut := c.mustRun("inputs", scanID, "--location", "path")
	if !strings.Contains(inputsOut, "user_id") {
		t.Errorf("scanner inputs --location path missing the discovered user_id path parameter:\n%s", inputsOut)
	}

	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	foundFinding := false
	for _, f := range rep.Findings {
		if f.VulnerabilityType == "sql_injection" && f.AffectedParameter == "user_id" {
			foundFinding = true
		}
	}
	if !foundFinding {
		t.Fatalf("report contains no sql_injection finding for the user_id path parameter: %+v", rep.Findings)
	}
	foundPathParam := false
	for _, p := range rep.Parameters {
		if p.Location == "path" && p.Name == "user_id" {
			foundPathParam = true
			if p.PathSegmentIndex < 0 {
				t.Errorf("PathSegmentIndex = %d, want >= 0 for a persisted path parameter", p.PathSegmentIndex)
			}
		}
	}
	if !foundPathParam {
		t.Fatalf("report contains no path-location user_id Parameter: %+v", rep.Parameters)
	}
}

func TestScanCmd_ActivePathParameter_AuthenticatedOrders_RealBinary(t *testing.T) {
	ip, port := authLabCLI(t)
	loginURL := fmt.Sprintf("http://%s:%d/login", ip, port)

	t.Setenv("E2E_PATHPARAM_USER", lab.AccountAUsername)
	t.Setenv("E2E_PATHPARAM_PASS", lab.AccountAPassword)
	extra := authIdentityConfig(loginURL, strconv.Itoa(port), "E2E_PATHPARAM_USER", "E2E_PATHPARAM_PASS", lab.AccountAUsername, lab.AccountAPassword)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--profile", "web", "--identity", "account")
	if !strings.Contains(out, "sql_injection") {
		t.Fatalf("output missing the expected sql_injection finding from the authenticated /orders/{id} path segment:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/orders/") {
		t.Errorf("report does not list an affected /orders/{id} endpoint:\n%s", mdOut)
	}
	if strings.Contains(mdOut, lab.AccountAPassword) {
		t.Fatal("SECURITY: the account password leaked into the generated report")
	}
}
