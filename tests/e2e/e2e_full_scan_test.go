// Phase 3.11 CLI end-to-end test: drives the built scanner binary
// through `scanner scan <target>` -- the unified full-pipeline command
// (task section 45) -- against a local httptest server only, and
// verifies its documented exit codes (task section 46).
package e2e

import (
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("not an *exec.ExitError: %v (%T)", err, err)
	return -1
}

func TestFullScan_TargetString_CompletesAndShowsFindings(t *testing.T) {
	bin := buildBinary(t)

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if strings.Contains(r.URL.RawQuery, "q=") {
			// Deliberately vulnerable-shaped: reflects the "q" parameter
			// unescaped into an HTML text context, so the real
			// xssreflected detector produces exactly one finding --
			// proving the full pipeline (not just recon) actually ran.
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>results for %s</body></html>", r.URL.Query().Get("q"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/?q=sakannerXSSPROBE123">search</a></body></html>`))
	}))
	defer srv.Close()

	host, port, err := splitServerAddr(srv)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	configContents := fmt.Sprintf(
		"storage:\n  dsn: %s\nscope:\n  allow_reserved_ranges: true\ncrawler:\n  enabled: true\n  max_depth: 1\n  max_pages: 5\nports:\n  default_ports: [%d]\n",
		dbPath, port,
	)
	if err := os.WriteFile(configPath, []byte(configContents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	c.mustRun("scope", "add", host, "--action", "allow", "--note", "e2e full-scan target")

	out, _, err := c.run("scan", host)
	if err != nil {
		t.Fatalf("scanner scan %s: %v\noutput: %s", host, err, out)
	}
	if !strings.Contains(out, "Status:   COMPLETED") && !strings.Contains(out, "Status:   COMPLETED_WITH_WARNINGS") {
		t.Fatalf("scan output missing a COMPLETED status:\n%s", out)
	}
	if !strings.Contains(out, "Scan ID:") || !strings.Contains(out, "Target:") {
		t.Errorf("scan output missing Scan ID/Target header:\n%s", out)
	}
	if !strings.Contains(out, "reflected_xss") {
		t.Errorf("scan output missing the expected reflected_xss finding:\n%s", out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("scan output missing the Summary line:\n%s", out)
	}
}

func TestFullScan_MissingTarget_ExitCode1(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	_, stderr, err := c.run("scan")
	if err == nil {
		t.Fatal("scan with no target/--target succeeded, want an error")
	}
	if code := exitCode(t, err); code != 1 {
		t.Errorf("exit code = %d, want 1 (generic error)", code)
	}
	if !strings.Contains(stderr, "target") {
		t.Errorf("stderr does not mention the missing target: %q", stderr)
	}
}

func TestFullScan_InvalidTarget_ExitCode2(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	out, _, err := c.run("scan", "not a valid target !! $(rm -rf /)")
	if err == nil {
		t.Fatalf("scan with a malformed target succeeded, want an error\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 2 {
		t.Errorf("exit code = %d, want 2 (scan failed)", code)
	}
	if !strings.Contains(out, "Status:   FAILED") {
		t.Errorf("output missing Status: FAILED:\n%s", out)
	}
}

func TestFullScan_OutOfScopeTarget_ExitCode2(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)
	// No `scope add` at all -- default-deny must abort the scan.

	out, _, err := c.run("scan", "not-authorized.example.test")
	if err == nil {
		t.Fatalf("scan against an out-of-scope target succeeded, want an error\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 2 {
		t.Errorf("exit code = %d, want 2 (scan failed)", code)
	}
	if !strings.Contains(out, "Status:   FAILED") {
		t.Errorf("output missing Status: FAILED:\n%s", out)
	}
}

func TestFullScan_Timeout_ExitCode3(t *testing.T) {
	bin := buildBinary(t)

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("<html><body>benign</body></html>"))
	}))
	defer srv.Close()
	host, port, err := splitServerAddr(srv)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	configContents := fmt.Sprintf("storage:\n  dsn: %s\nscope:\n  allow_reserved_ranges: true\nports:\n  default_ports: [%d]\n", dbPath, port)
	if err := os.WriteFile(configPath, []byte(configContents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)
	c.mustRun("scope", "add", host, "--action", "allow")

	out, _, err := c.run("scan", host, "--timeout", "1ns")
	if err == nil {
		t.Fatalf("scan with a 1ns timeout succeeded, want cancellation\noutput: %s", out)
	}
	if code := exitCode(t, err); code != 3 {
		t.Errorf("exit code = %d, want 3 (cancelled)", code)
	}
	if !strings.Contains(out, "Status:   CANCELLED") {
		t.Errorf("output missing Status: CANCELLED:\n%s", out)
	}
}
