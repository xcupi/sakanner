// Phase 3.28 CLI end-to-end tests: `scanner detectors list` and a real
// scan through the actual compiled binary, proving open-redirect-active
// (internal/detectors/openredirectactive) is registered but stays
// disabled by default -- no production-configured, known, out-of-scope
// canary destination ships with this build, mirroring ssrf-active/
// traversal-active's own identical precedent (Phase 3.25/3.27). The
// full, real, positive/negative end-to-end proof (against the lab's
// own known destination) lives in
// lab/phase3_28_openredirect_active_test.go -- this file only proves
// the CLI-level registration/enablement contract and that the disabled
// detector never silently produces a finding.
package e2e

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDetectorsCmd_OpenRedirectActive_RegisteredButDisabled(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("detectors", "list")
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "open-redirect-active" {
			found = true
			if len(fields) < 2 || fields[1] != "disabled" {
				t.Errorf("open-redirect-active status line = %q, want disabled (no production-configured destination ships with this build)", line)
			}
		}
	}
	if !found {
		t.Fatalf("detectors list is missing open-redirect-active entirely:\n%s", out)
	}
}

// TestScanCmd_OpenRedirectActive_DisabledByDefault_NeverProducesFinding
// proves the same "do not silently enable an expensive active
// detector globally" rule ssrf-active/path-traversal-active's own e2e
// tests prove: a real scan (--profile web, so detection actually
// runs) against a plain, redirect-shaped GET endpoint never produces
// an open_redirect finding, since open-redirect-active stays disabled
// with no destination configured.
func TestScanCmd_OpenRedirectActive_DisabledByDefault_NeverProducesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/go?next=/dashboard">go</a></body></html>`))
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
	if strings.Contains(out, "\nopen_redirect") || strings.Contains(out, "\topen_redirect\t") {
		t.Fatalf("an open_redirect finding appeared despite open-redirect-active being disabled by default:\n%s", out)
	}
}
