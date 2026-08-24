// Phase 3.27 CLI end-to-end tests: `scanner detectors list` and a real
// scan through the actual compiled binary, proving path-traversal-active
// (internal/detectors/traversalactive) is registered but stays
// disabled by default -- no production-configured
// traversal.TraversalCase (a known relative path + its confirmation
// marker) ships with this build, mirroring ssrf-active/idor-active's
// own identical precedent (Phase 3.25/3.24). The full, real, positive/
// negative end-to-end proof (against the lab's own synthetic
// filesystem and marker) lives in lab/phase3_27_traversal_active_test.go
// -- this file only proves the CLI-level registration/enablement
// contract and that the disabled detector never silently produces a
// finding, mirroring e2e_ssrf_active_test.go's exact pattern.
package e2e

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDetectorsCmd_PathTraversalActive_RegisteredButDisabled(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("detectors", "list")
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "path-traversal-active" {
			found = true
			if len(fields) < 2 || fields[1] != "disabled" {
				t.Errorf("path-traversal-active status line = %q, want disabled (no production-configured TraversalCase ships with this build)", line)
			}
		}
	}
	if !found {
		t.Fatalf("detectors list is missing path-traversal-active entirely:\n%s", out)
	}
}

// TestScanCmd_PathTraversalActive_DisabledByDefault_NeverProducesFinding
// proves the same "do not silently enable an expensive active detector
// globally" rule ssrf-active's own e2e test proves: a real scan
// (--profile web, so detection actually runs) against a plain,
// file-parameter-shaped GET endpoint never produces a path_traversal
// finding from path-traversal-active, since it stays disabled with no
// TraversalCase configured. (The pre-existing "traversal" detector is
// ALSO disabled by default -- see docs/phase-3-6-path-traversal.md --
// so no path_traversal finding of any kind is expected here.)
func TestScanCmd_PathTraversalActive_DisabledByDefault_NeverProducesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/download?file=report.txt">download</a></body></html>`))
	}))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)

	configPath := writeConfig(t, "ports:\n  default_ports: ["+port+"]\n")
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	portInt, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	out := c.mustRun("scan", host, "--profile", "web", "--ports", strconv.Itoa(portInt))
	if strings.Contains(out, "\npath_traversal") || strings.Contains(out, "\tpath_traversal\t") {
		t.Fatalf("a path_traversal finding appeared despite path-traversal-active being disabled by default:\n%s", out)
	}
}
