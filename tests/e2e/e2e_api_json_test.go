// Phase 3.18 CLI end-to-end tests: live JSON RESPONSE-body discovery
// and `scanner inputs`'s new PROVENANCE/API/IDENTITY columns, through
// the real built binary.
package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScanCmd_JSONResponseDiscovery_ResponseFieldProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/data" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"user_id":1001,"email":"alice@example.test"}`))
			return
		}
		w.Write([]byte(`<html><body><a href="/api/data">api</a></body></html>`))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	_, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\n", portStr))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", u.Hostname())

	out := c.mustRun("scan", u.Hostname(), "--profile", "web")
	scanID := extractFullScanID(t, out)

	inputsOut := c.mustRun("inputs", scanID)
	for _, want := range []string{"user_id", "email", "RESPONSE_FIELD", "json"} {
		if !strings.Contains(inputsOut, want) {
			t.Errorf("scanner inputs output missing %q:\n%s", want, inputsOut)
		}
	}

	// --provenance filter: only RESPONSE_FIELD rows.
	responseOnly := c.mustRun("inputs", scanID, "--provenance", "RESPONSE_FIELD")
	if !strings.Contains(responseOnly, "user_id") {
		t.Errorf("--provenance RESPONSE_FIELD output missing user_id:\n%s", responseOnly)
	}
	if strings.Contains(responseOnly, "REQUEST_INPUT") {
		t.Errorf("--provenance RESPONSE_FIELD output must not contain REQUEST_INPUT rows:\n%s", responseOnly)
	}
}

func TestScanCmd_APICandidateClassification_ContentTypeEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/data" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Write([]byte(`<html><body><a href="/api/data">api</a></body></html>`))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	_, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\n", portStr))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", u.Hostname())

	out := c.mustRun("scan", u.Hostname(), "--profile", "web")
	scanID := extractFullScanID(t, out)

	inputsOut := c.mustRun("inputs", scanID)
	// The "ok" input's row must show API=true (its endpoint /api/data
	// was fetched and returned a JSON content type). tabwriter aligns
	// columns with spaces, not literal tabs, so match on whitespace-
	// split fields: NAME=ok at index 3, API at index 7.
	found := false
	for _, line := range strings.Split(inputsOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[3] == "ok" && fields[7] == "true" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an 'ok' input row with NAME=ok and API=true, got:\n%s", inputsOut)
	}
}
