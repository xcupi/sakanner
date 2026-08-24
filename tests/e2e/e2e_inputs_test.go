// Phase 3.13 CLI end-to-end tests: `scanner scan`'s new "Inputs:"
// block and the new `scanner inputs <scan-id>` command, through the
// real built binary.
package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// extractFullScanID reads the "Scan ID:  <uuid>" line printScanResult
// prints for the full-pipeline `scanner scan <target>` path -- distinct
// from e2e_test.go's extractScanID, which parses the unrelated legacy
// `--target <id>` recon-only path's own "scan <uuid> finished..." line.
func extractFullScanID(t *testing.T, output string) string {
	t.Helper()
	m := regexp.MustCompile(`Scan ID:\s+(\S+)`).FindStringSubmatch(output)
	if m == nil {
		t.Fatalf("could not find \"Scan ID:\" in output: %q", output)
	}
	return m[1]
}

func TestScanCmd_InputsBlock_QueryAndFormDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" {
			w.Write([]byte("<html><body>results</body></html>"))
			return
		}
		w.Write([]byte(`<html><body>
			<a href="/search?q=hello&page=2">search</a>
			<form action="/login" method="post">
				<input name="username" type="text">
				<input name="password" type="password">
			</form>
		</body></html>`))
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
	if !strings.Contains(out, "Inputs:") {
		t.Fatalf("output missing \"Inputs:\" block:\n%s", out)
	}
	if !strings.Contains(out, "Discovered: 4") {
		t.Errorf("output missing \"Discovered: 4\" (q, page, username, password):\n%s", out)
	}
	if !strings.Contains(out, "Unique endpoints with inputs: 2") {
		t.Errorf("output missing \"Unique endpoints with inputs: 2\":\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	inputsOut := c.mustRun("inputs", scanID)
	for _, want := range []string{"q", "page", "username", "password", "query", "form", "PARAMETER", "FORM_FIELD"} {
		if !strings.Contains(inputsOut, want) {
			t.Errorf("scanner inputs output missing %q:\n%s", want, inputsOut)
		}
	}
}

func TestScanCmd_InputsBlock_ReconProfile_ZeroInputs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/search?q=hello">search</a></body></html>`))
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

	out := c.mustRun("scan", u.Hostname(), "--profile", "recon")
	if !strings.Contains(out, "Discovered: 0") {
		t.Errorf("output missing \"Discovered: 0\" under the recon profile:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	inputsOut := c.mustRun("inputs", scanID)
	if !strings.Contains(inputsOut, "no inputs discovered") {
		t.Errorf("scanner inputs output = %q, want \"no inputs discovered\"", inputsOut)
	}
}

func TestInputsCmd_LocationFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" {
			w.Write([]byte("ok"))
			return
		}
		w.Write([]byte(`<html><body>
			<a href="/search?q=hello">search</a>
			<form action="/login" method="post"><input name="username" type="text"></form>
		</body></html>`))
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

	queryOut := c.mustRun("inputs", scanID, "--location", "query")
	if !strings.Contains(queryOut, "q") || strings.Contains(queryOut, "username") {
		t.Errorf("--location query output = %q, want q present and username absent", queryOut)
	}

	formOut := c.mustRun("inputs", scanID, "--location", "form")
	if !strings.Contains(formOut, "username") || strings.Contains(formOut, regexp.QuoteMeta("q\t")) {
		t.Errorf("--location form output = %q, want username present", formOut)
	}
}

func TestScanCmd_InputsBlock_SensitiveFieldRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="password" type="password" value="hunter2plaintext">
			</form>
		</body></html>`))
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
	if strings.Contains(inputsOut, "hunter2plaintext") {
		t.Errorf("secret value leaked in scanner inputs output:\n%s", inputsOut)
	}
}
