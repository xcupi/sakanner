// Phase 3.30 CLI end-to-end test: the real built binary, driven
// through a real scan against the real lab, its real JSON report
// output parsed back into []models.Finding (exactly as an external
// consumer would receive it), fed into internal/chains.Correlate.
//
// internal/chains has no CLI subcommand of its own in this phase (see
// docs/phase-3-30-correlation-chain-foundation.md section 13 for why
// -- a deliberate, documented scope decision, not an oversight) -- so
// this test's own job is to prove the package works correctly against
// REAL, externally-serialized finding data produced by the actual
// compiled binary, round-tripped through JSON exactly as it would be
// for any future consumer.
package e2e

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/chains"
	"sakanner/internal/reporting"
)

func TestChains_RealCLIReportOutput_CorrelatesSafely(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, "crawler:\n  enabled: true\n  max_depth: 3\n  max_pages: 100\nports:\n  default_ports: ["+strconv.Itoa(port)+"]\n")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out := c.mustRun("scan", ip, "--ports", strconv.Itoa(port))
	if !strings.Contains(out, "Findings:") && !strings.Contains(out, "finding") {
		t.Fatalf("scan output does not look like it reported any findings:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	var rep reporting.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("unmarshal report json: %v\n%s", err, jsonOut)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected at least one real finding in the report to make this test meaningful")
	}

	res := chains.Correlate(rep.Findings, chains.DefaultLimits())

	findingByID := map[string]bool{}
	for _, f := range rep.Findings {
		findingByID[f.ID] = true
		if f.ScanID != scanID && f.ScanID != "" {
			// Sanity check on the report itself, not chains -- every
			// finding in ONE scan's own report must carry that scan's
			// own ID.
			t.Errorf("report finding %s has ScanID %q, want %q", f.ID, f.ScanID, scanID)
		}
	}
	for _, r := range res.Relations {
		if !findingByID[r.FindingAID] || !findingByID[r.FindingBID] {
			t.Errorf("relation references a finding ID absent from the real report: %+v", r)
		}
	}
	for _, cand := range res.Candidates {
		for _, fid := range cand.FindingIDs {
			if !findingByID[fid] {
				t.Errorf("candidate references a finding ID absent from the real report: %+v", cand)
			}
		}
	}
}
