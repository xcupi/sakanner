// Package e2e drives the built scanner binary through a full CLI story
// (target add -> scope add -> scan -> status -> findings -> report)
// against a local httptest server only -- it never touches the live
// internet, so it's safe to run in any environment including CI.
package e2e

import (
	"bytes"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// buildBinary compiles cmd/scanner once for the whole test run.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "scanner")

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", bin, "./cmd/scanner")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/scanner: %v\n%s", err, out)
	}
	return bin
}

type cli struct {
	t      *testing.T
	bin    string
	config string
}

func newCLI(t *testing.T, bin, configPath string) *cli {
	return &cli{t: t, bin: bin, config: configPath}
}

func (c *cli) run(args ...string) (stdout, stderr string, err error) {
	c.t.Helper()
	fullArgs := append([]string{"--config", c.config}, args...)
	cmd := exec.Command(c.bin, fullArgs...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func (c *cli) mustRun(args ...string) string {
	c.t.Helper()
	out, errOut, err := c.run(args...)
	if err != nil {
		c.t.Fatalf("scanner %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, out, errOut)
	}
	return out
}

var idRe = regexp.MustCompile(`id=([0-9a-f-]{36})`)

func extractID(t *testing.T, output string) string {
	t.Helper()
	m := idRe.FindStringSubmatch(output)
	if m == nil {
		t.Fatalf("could not find id= in output: %q", output)
	}
	return m[1]
}

func TestFullStory_TargetAddScopeAddScanStatusFindingsReport(t *testing.T) {
	bin := buildBinary(t)

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte("<html><head><title>E2E Test Site</title></head></html>"))
	}))
	defer srv.Close()

	host, port, err := splitServerAddr(srv)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	configContents := fmt.Sprintf("storage:\n  dsn: %s\nscope:\n  allow_reserved_ranges: true\ncrawler:\n  enabled: true\n  max_depth: 1\n  max_pages: 5\n", dbPath)
	if err := os.WriteFile(configPath, []byte(configContents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := newCLI(t, bin, configPath)

	// 1. target add
	targetOut := c.mustRun("target", "add", host, "--note", "e2e test target")
	targetID := extractID(t, targetOut)

	listOut := c.mustRun("target", "list")
	if !strings.Contains(listOut, targetID) {
		t.Errorf("target list missing added target:\n%s", listOut)
	}

	// 2. scope add
	scopeOut := c.mustRun("scope", "add", host, "--action", "allow", "--note", "e2e authorization")
	extractID(t, scopeOut) // just verify it parses; not needed further

	scopeListOut := c.mustRun("scope", "list")
	if !strings.Contains(scopeListOut, host) {
		t.Errorf("scope list missing added rule:\n%s", scopeListOut)
	}

	// 3. scan
	scanOut := c.mustRun("scan", "--target", targetID, "--ports", fmt.Sprintf("%d", port))
	if !strings.Contains(scanOut, "status completed") && !strings.Contains(scanOut, "finished with status completed") {
		t.Fatalf("scan did not report completed status:\n%s", scanOut)
	}
	scanID := extractScanID(t, scanOut)

	// 4. status
	statusOut := c.mustRun("status", scanID)
	for _, want := range []string{"status: completed", "hosts: 1", "services: 1", "http_services: 1", "endpoints: 1"} {
		if !strings.Contains(statusOut, want) {
			t.Errorf("status output missing %q:\n%s", want, statusOut)
		}
	}

	// 5. findings (expected empty in Phase 1)
	findingsOut := c.mustRun("findings", "--scan", scanID)
	if !strings.Contains(findingsOut, "no findings") {
		t.Errorf("expected 'no findings', got:\n%s", findingsOut)
	}

	// 6. report (both formats)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	for _, want := range []string{"E2E Test Site", "nginx", scanID} {
		if !strings.Contains(mdOut, want) {
			t.Errorf("markdown report missing %q:\n%s", want, mdOut)
		}
	}

	jsonOut := c.mustRun("report", "--scan", scanID, "--format", "json")
	if !strings.Contains(jsonOut, `"status": "completed"`) {
		t.Errorf("json report missing completed status:\n%s", jsonOut)
	}
	if !strings.Contains(jsonOut, `"name": "nginx"`) {
		t.Errorf("json report missing fingerprinted technology:\n%s", jsonOut)
	}
}

func TestFullStory_ScopeDenialAbortsScan(t *testing.T) {
	bin := buildBinary(t)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := newCLI(t, bin, configPath)

	targetOut := c.mustRun("target", "add", "not-authorized.test")
	targetID := extractID(t, targetOut)

	// No scope rules added -- default deny must abort the scan.
	_, _, err := c.run("scan", "--target", targetID)
	if err == nil {
		t.Fatal("expected scan to fail for a target with no scope rule authorizing it")
	}
}

func TestToolsStatus_ReportsAllFiveIntegrations(t *testing.T) {
	bin := buildBinary(t)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	out := c.mustRun("tools", "status")
	// Detection status (found/not found) depends on what's actually
	// installed on the machine running this test, so only the tool names
	// and their default "auto" backend are asserted here -- both are
	// deterministic regardless of environment.
	for _, want := range []string{"subfinder", "dnsx", "naabu", "httpx", "katana", "backend=auto"} {
		if !strings.Contains(out, want) {
			t.Errorf("tools status output missing %q:\n%s", want, out)
		}
	}
}

func splitServerAddr(srv *httptest.Server) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		return "", 0, err
	}
	portNum, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, portNum, nil
}

func extractScanID(t *testing.T, output string) string {
	t.Helper()
	// Output looks like: "scan <uuid> finished with status completed"
	fields := strings.Fields(output)
	for i, f := range fields {
		if f == "scan" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	t.Fatalf("could not extract scan ID from output: %q", output)
	return ""
}
