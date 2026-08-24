// Phase 3.11.2 CLI end-to-end tests: drives the built scanner binary
// through the REAL default config.Load path (never a manually
// constructed orchestration.Pipeline) against the REAL Phase 3 vuln
// lab (imported from sakanner/lab, which exposes it via exported,
// non-test symbols precisely so it can be reused here) -- proving
// detection readiness/zero-detector observability end to end, through
// the actual binary (task section 11).
//
// sakanner/lab (formerly sakanner/lab) lives at the repository's
// top level, a sibling of cmd/, internal/, pkg/, and tests/ -- not
// nested inside tests/ -- per the Lab Isolation Review: it is an
// external test target the production scanner never imports, and this
// file is the ONE place in the whole repository that imports it to
// drive the real binary against it. See docs/lab-isolation-review.md.
package e2e

import (
	"fmt"
	"html"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sakanner/lab"
)

// vulnLabCLI starts the real Phase 3 vuln lab and returns its bare IP
// (127.0.0.21, a real loopback address any local process can dial) and
// port, for use as a `scanner scan <ip> --ports <port>` target -- the
// lab's dns.FakeResolver only resolves fake hostnames like
// vuln.scanner.test WITHIN the test process itself, so a real CLI
// subprocess (which uses the real system resolver) must be pointed at
// the lab's literal, real TCP address instead.
func vulnLabCLI(t *testing.T) (ip string, port int) {
	t.Helper()
	gt, err := lab.LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	l, err := lab.StartWithVulnerabilities(gt)
	if err != nil {
		t.Fatalf("StartWithVulnerabilities: %v", err)
	}
	t.Cleanup(l.Close)

	host, portStr, err := net.SplitHostPort(l.VulnAddr)
	if err != nil {
		t.Fatalf("split lab addr %q: %v", l.VulnAddr, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	contents := fmt.Sprintf("storage:\n  dsn: %s\nscope:\n  allow_reserved_ranges: true\n%s", dbPath, extra)
	if err := os.WriteFile(configPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

// --- Task section 1: default config, crawler disabled -----------------

// TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable:
// Phase 3.12 changed WHAT a bare, no-flags, no-crawler-config default
// scan reports here (see docs/phase-3-12-scan-profiles.md
// "Configuration precedence"): with no --profile and no
// crawler.enabled: true in config, the "recon" default profile now
// applies, so this is reported as DETECTION_DISABLED_BY_PROFILE, not
// the Phase 3.11.2-era NOT_RUN/DETECTION_NOT_RUN warning -- a more
// accurate label for behavior that has not actually changed (crawler
// still off, detection still doesn't run, findings still zero). The
// underlying safety property this test exists to pin down (a plain
// default scan's zero detector runs must be OBSERVABLE, never
// misreadable as "checked, found nothing") still holds, just via a
// different, more precise state; see
// TestDefaultCLI_WebProfile_NoEligibleEndpoints_ReportsNotRun below for
// direct coverage of the (still fully reachable) NOT_RUN state itself.
func TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable(t *testing.T) {
	ip, port := vulnLabCLI(t)

	// No "crawler:" section and no --profile flag at all -- the real
	// config.Load default path, exactly what an operator gets from a
	// plain config.yaml with no crawler override and no explicit
	// profile choice.
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out, _, err := c.run("scan", ip)
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}

	// Recon must have genuinely succeeded (host/service/http_service
	// discovery all worked) -- this is not a scope or recon failure.
	// Disabled-by-profile is expected, policy-driven behavior, not an
	// anomaly, so the scan is a plain COMPLETED, never
	// COMPLETED_WITH_WARNINGS.
	if !strings.Contains(out, "Status:   COMPLETED") || strings.Contains(out, "COMPLETED_WITH_WARNINGS") {
		t.Errorf("output missing a plain COMPLETED status:\n%s", out)
	}
	if !strings.Contains(out, "Profile:  recon") {
		t.Errorf("output missing \"Profile:  recon\" (the resolved default):\n%s", out)
	}
	for _, want := range []string{
		"Detection:",
		"Policy enabled: false",
		"Reason: profile disables vulnerability detection",
		"Eligible targets: 0",
		"Detector runs: 0",
		"Raw findings: 0",
		"Canonical findings: 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Registered: 14") {
		t.Errorf("output missing accurate registry count (14 registered -- Phase 3.19 added xss-reflected-active, Phase 3.20 added sqli-active, Phase 3.24 added idor-active, Phase 3.25 added ssrf-active, Phase 3.26 added command-injection-active, Phase 3.27 added path-traversal-active, Phase 3.28 added open-redirect-active, Phase 3.29 added ssti-active):\n%s", out)
	}
	if !strings.Contains(out, "vulnerability detection is disabled by the active scan profile") {
		t.Errorf("output's empty-findings line does not name the profile-disabled state:\n%s", out)
	}
	if strings.Contains(out, "detectors executed, no vulnerabilities found") {
		t.Error("output falsely claims detectors executed and found nothing")
	}
}

// TestDefaultCLI_WebProfile_NoEligibleEndpoints_ReportsNotRun keeps the
// pre-3.12 NOT_RUN state (detection genuinely attempted, zero eligible
// targets discovered) directly, explicitly exercised end to end --
// Phase 3.12's task requirement that the existing State A/B/C
// distinction "must remain intact," not merely preserved in code but
// still reachable and tested. Unlike the recon-default case above,
// this scan explicitly opts into detection via --profile web, but the
// crawled target itself has nothing parameterized to find.
func TestDefaultCLI_WebProfile_NoEligibleEndpoints_ReportsNotRun(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/about">about</a></body></html>`))
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

	out, _, err := c.run("scan", u.Hostname(), "--profile", "web")
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "Profile:  web") {
		t.Errorf("output missing \"Profile:  web\":\n%s", out)
	}
	if !strings.Contains(out, "Policy enabled: true") {
		t.Errorf("output missing \"Policy enabled: true\" (web profile permits detection):\n%s", out)
	}
	if !strings.Contains(out, "Status:   COMPLETED_WITH_WARNINGS") {
		t.Errorf("output missing COMPLETED_WITH_WARNINGS (NOT_RUN is a warning, unlike disabled-by-profile):\n%s", out)
	}
	if !strings.Contains(out, "DETECTION_NOT_RUN") {
		t.Errorf("output missing the DETECTION_NOT_RUN warning:\n%s", out)
	}
	if strings.Contains(out, "Reason: profile disables vulnerability detection") {
		t.Error("output shows the disabled-by-profile reason on a web-profile scan")
	}
}

// --- Task section 8-9: crawler enabled, positive detection -------------

func TestDefaultCLI_CrawlerEnabled_PositiveDetection(t *testing.T) {
	ip, port := vulnLabCLI(t)

	configPath := writeConfig(t, fmt.Sprintf(
		"ports:\n  default_ports: [%d]\ncrawler:\n  enabled: true\n  max_depth: 2\n  max_pages: 30\n", port,
	))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out, _, err := c.run("scan", ip)
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "Status:   COMPLETED") {
		t.Fatalf("output missing a COMPLETED status:\n%s", out)
	}
	if strings.Contains(out, "Eligible targets: 0") {
		t.Errorf("output shows 0 eligible targets despite the crawler being enabled against a real vulnerable app:\n%s", out)
	}
	if strings.Contains(out, "Detector runs: 0") {
		t.Errorf("output shows 0 detector runs despite eligible targets existing:\n%s", out)
	}
	// xssreflected is enabled by default and needs no operator config,
	// so at least a reflected_xss finding is expected from this lab.
	if !strings.Contains(out, "reflected_xss") {
		t.Errorf("output missing the expected reflected_xss finding:\n%s", out)
	}
	if !strings.Contains(out, "detectors executed, no vulnerabilities found") && !strings.Contains(out, "CRITICAL:") && !strings.Contains(out, "HIGH:") && !strings.Contains(out, "MEDIUM:") {
		t.Errorf("output has neither a findings table nor the state-A empty-findings line:\n%s", out)
	}
}

// --- Task section 10: crawler enabled, benign target, no findings ------

func TestDefaultCLI_CrawlerEnabled_BenignTarget_DetectorsRanFoundNothing(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/search" {
			fmt.Fprintf(w, "<html><body>results for %s</body></html>", html.EscapeString(r.URL.Query().Get("q")))
			return
		}
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

	configPath := writeConfig(t, fmt.Sprintf(
		"ports:\n  default_ports: [%s]\ncrawler:\n  enabled: true\n  max_depth: 2\n  max_pages: 10\n", portStr,
	))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", u.Hostname())

	out, _, err := c.run("scan", u.Hostname())
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, "Status:   COMPLETED") || strings.Contains(out, "COMPLETED_WITH_WARNINGS") {
		t.Errorf("output missing a plain COMPLETED status (state A: detectors ran and genuinely found nothing, no warning expected):\n%s", out)
	}
	if strings.Contains(out, "Detector runs: 0") {
		t.Errorf("output shows 0 detector runs despite a real parameterized endpoint being crawlable:\n%s", out)
	}
	if !strings.Contains(out, "(none -- detectors executed, no vulnerabilities found)") {
		t.Errorf("output missing the state-A empty-findings message (must say \"executed,\" never \"skipped\"):\n%s", out)
	}
	if strings.Contains(out, "no vulnerability detectors were executed") {
		t.Error("output falsely claims detection was skipped, despite detectors having actually run")
	}
}
