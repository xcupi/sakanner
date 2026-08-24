// Phase 3.25 CLI end-to-end tests: `scanner detectors list` and a
// real scan through the actual compiled binary, proving ssrf-active
// (internal/detectors/ssrfactive) is registered but stays disabled by
// default -- no production-reachable callback service ships with this
// build (the SAME honest, pre-existing gap internal/detectors/ssrf
// itself already documents). The full, real, positive/negative
// end-to-end proof (against the real callback server, which only the
// lab provides) lives in lab/phase3_25_ssrf_active_test.go -- this
// file only proves the CLI-level registration/enablement contract,
// mirroring how the pre-existing "ssrf" detector has never had its
// own dedicated CLI e2e test either (nothing to prove via the real
// binary beyond registration, since no production callback service
// exists in this build).
package e2e

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDetectorsCmd_SSRFActive_RegisteredButDisabled(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("detectors", "list")
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "ssrf-active" {
			found = true
			if len(fields) < 2 || fields[1] != "disabled" {
				t.Errorf("ssrf-active status line = %q, want disabled (no production-reachable callback service ships with this build)", line)
			}
		}
	}
	if !found {
		t.Fatalf("detectors list is missing ssrf-active entirely:\n%s", out)
	}
}

// TestScanCmd_SSRFActive_DisabledByDefault_NeverProducesFinding proves
// task section 16's own "do not silently enable an expensive active
// detector globally" -- a real scan (--profile web, so detection
// actually runs) against a plain, GET-query URL-shaped-parameter
// fixture never produces an ssrf finding, since ssrf-active stays
// disabled with no callback client configured.
func TestScanCmd_SSRFActive_DisabledByDefault_NeverProducesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/fetch?url=http://example.test/">fetch</a></body></html>`))
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
	if strings.Contains(out, "\nssrf") || strings.Contains(out, "\tssrf\t") {
		t.Fatalf("an ssrf finding appeared despite ssrf-active being disabled by default:\n%s", out)
	}
}
