// Phase 3.12 CLI end-to-end tests: `scanner profiles list/show`,
// `scanner scan --profile <name>` against real targets (the Phase 3
// vuln lab and locally-built httptest fixtures), invalid-profile
// handling, and the config-precedence rules -- all through the real
// built binary and the real default config.Load path, matching the
// established pattern from e2e_detection_readiness_test.go.
package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// --- scanner profiles list/show ----------------------------------------

func TestProfilesListCmd(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out := c.mustRun("profiles", "list")
	for _, want := range []string{"NAME", "DESCRIPTION", "CRAWLER", "DETECTION", "VERIFICATION", "RESOURCE CLASS", "recon", "web", "deep", "(default)"} {
		if !strings.Contains(out, want) {
			t.Errorf("profiles list output missing %q:\n%s", want, out)
		}
	}
}

func TestProfilesShowCmd(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	recon := c.mustRun("profiles", "show", "recon")
	if !strings.Contains(recon, "Enabled:   false") {
		t.Errorf("profiles show recon missing crawler disabled:\n%s", recon)
	}
	if !strings.Contains(recon, "(default)") {
		t.Errorf("profiles show recon missing (default) marker:\n%s", recon)
	}

	web := c.mustRun("profiles", "show", "web")
	if !strings.Contains(web, "Enabled:   true") {
		t.Errorf("profiles show web missing crawler enabled:\n%s", web)
	}

	deep := c.mustRun("profiles", "show", "deep")
	if !strings.Contains(deep, "Enabled:   true") {
		t.Errorf("profiles show deep missing crawler enabled:\n%s", deep)
	}
	if !strings.Contains(deep, "Note: profiles never grant authorization") {
		t.Errorf("profiles show deep missing the authorization-disclaimer note:\n%s", deep)
	}
}

func TestProfilesShowCmd_UnknownProfile(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out, errOut, err := c.run("profiles", "show", "bogus")
	if err == nil {
		t.Fatal("profiles show bogus succeeded, want a non-zero exit")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != exitGenericErrorForTest {
		t.Errorf("exit code = %v, want %d", err, exitGenericErrorForTest)
	}
	combined := out + errOut
	if !strings.Contains(combined, `unknown scan profile "bogus"`) {
		t.Errorf("output missing required error phrase:\nstdout: %s\nstderr: %s", out, errOut)
	}
	if !strings.Contains(combined, "Available profiles:") {
		t.Errorf("output missing \"Available profiles:\":\nstdout: %s\nstderr: %s", out, errOut)
	}
}

// exitGenericErrorForTest mirrors cmd/scanner/exitcode.go's
// exitGenericError -- duplicated here (a plain int, not imported: this
// package deliberately never imports cmd/scanner, only drives the
// built binary) rather than depending on cmd/scanner's internal
// package.
const exitGenericErrorForTest = 1

// --- scanner scan --profile: invalid profile fails cleanly -------------

// TestScanCmd_InvalidProfile_CleanFailure: task's exact requirement --
// non-zero exit, an error naming the invalid profile and listing valid
// ones, and (critically) no scan job created -- an INVALID profile
// must be rejected before SCOPE, before RECON, before anything that
// would create a scan_jobs row or touch the network. Using an
// intentionally out-of-scope, unreachable target (198.51.100.1,
// RFC 5737 TEST-NET-2, never added to scope) proves this: if profile
// resolution ran AFTER scope validation, this would fail with a scope
// error instead, not the unknown-profile error -- the fact that we
// see the profile error at all proves resolution happened first.
func TestScanCmd_InvalidProfile_CleanFailure(t *testing.T) {
	configPath := writeConfig(t, "")
	c := newCLI(t, buildBinary(t), configPath)

	out, errOut, err := c.run("scan", "198.51.100.1", "--profile", "bogus-profile")
	if err == nil {
		t.Fatal("scan with an invalid --profile succeeded, want a non-zero exit")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != exitGenericErrorForTest {
		t.Errorf("exit code = %v, want %d (generic usage error, not a scan/scope failure code)", err, exitGenericErrorForTest)
	}
	combined := out + errOut
	if !strings.Contains(combined, `unknown scan profile "bogus-profile"`) {
		t.Errorf("output missing required error phrase:\nstdout: %s\nstderr: %s", out, errOut)
	}
	if !strings.Contains(combined, "Available profiles:") {
		t.Errorf("output missing \"Available profiles:\":\nstdout: %s\nstderr: %s", out, errOut)
	}
	if strings.Contains(combined, "Scan ID:") {
		t.Error("output contains a Scan ID -- a scan job was apparently created despite the invalid profile")
	}

	targets := c.mustRun("target", "list")
	if strings.Contains(targets, "198.51.100.1") {
		t.Errorf("target list shows the invalid-profile target was registered -- a target/scan job was created despite the profile error:\n%s", targets)
	}
}

// --- scanner scan --profile web/deep: real detection ---------------------

func TestScanCmd_ProfileWeb_AgainstVulnLab_RealFinding(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out, _, err := c.run("scan", ip, "--profile", "web")
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "Profile:  web\n") {
		t.Errorf("output missing \"Profile:  web\":\n%s", out)
	}
	if !strings.Contains(out, "Policy enabled: true") {
		t.Errorf("output missing \"Policy enabled: true\":\n%s", out)
	}
	if !strings.Contains(out, "reflected_xss") {
		t.Errorf("output missing the expected reflected_xss finding:\n%s", out)
	}
	if !strings.Contains(out, "Status:   COMPLETED") {
		t.Errorf("output missing a COMPLETED status:\n%s", out)
	}
}

func TestScanCmd_ProfileDeep_AgainstVulnLab_DetectionExecutes(t *testing.T) {
	ip, port := vulnLabCLI(t)
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%d]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", ip)

	out, _, err := c.run("scan", ip, "--profile", "deep")
	if err != nil {
		t.Fatalf("scan: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "Profile:  deep\n") {
		t.Errorf("output missing \"Profile:  deep\":\n%s", out)
	}
	if !strings.Contains(out, "Policy enabled: true") {
		t.Errorf("output missing \"Policy enabled: true\":\n%s", out)
	}
	if strings.Contains(out, "Detector runs: 0") {
		t.Errorf("output shows 0 detector runs under the deep profile against a real vulnerable app:\n%s", out)
	}
	if !strings.Contains(out, "Status:   COMPLETED") {
		t.Errorf("output missing a COMPLETED status:\n%s", out)
	}
}

// chainPageServer serves a linear chain of n parameterized pages
// (/p/0?id=0 -> /p/1?id=1 -> ... -> /p/(n-1)?id=(n-1), each page's only
// link is to the next), reachable from "/" -- the "many-page crawler
// target" fixture task section "TEST LAB" requires, built inline
// rather than added to lab since it needs no vulnerability
// content and no fixed lab IP, just enough chained, parameterized
// pages to make crawl DEPTH (task's "web": max_depth=2 vs "deep":
// max_depth=4) the thing that bounds discovery -- a fan-out design
// (one page linking to many) does not exercise MaxDepth at all, since
// every linked page is already reachable at depth 1 regardless of how
// deep a profile is willing to go.
func chainPageServer(n int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/p/0?id=0">start</a></body></html>`))
	})
	for i := 0; i < n; i++ {
		i := i
		mux.HandleFunc(fmt.Sprintf("/p/%d", i), func(w http.ResponseWriter, r *http.Request) {
			if i+1 < n {
				fmt.Fprintf(w, `<html><body><a href="/p/%d?id=%d">next</a></body></html>`, i+1, i+1)
				return
			}
			w.Write([]byte("<html><body>end of chain</body></html>"))
		})
	}
	return httptest.NewServer(mux)
}

// TestScanCmd_DeepProfile_CrawlsMoreThanWeb_ButBounded is the direct,
// end-to-end proof of task's "deep is deeper than web, but still
// bounded, never unlimited" requirement: a 30-page chain, far deeper
// than either profile's own MaxDepth bound (web: 2, deep: 4), so
// neither profile can possibly reach the end of the chain -- deep must
// discover strictly more eligible targets than web, and the number of
// PAGES actually crawled (Crawl: Public URLs) must stay strictly
// fewer than the 30 that exist.
//
// The "boundedness" check was originally asserted directly on
// EligibleTargets (deepEligible < totalPages) -- correct only as long
// as each crawled page contributed roughly one eligible target
// (query parameter "id"). Phase 3.23 wired up path-parameter
// discovery: this fixture's own "/p/{n}" numeric path segment is now
// ALSO correctly inferred as a path-location eligible target (one
// more per page, alongside the existing query one), so
// EligibleTargets can legitimately exceed the page count even though
// the CRAWL itself remains just as bounded as before -- more targets
// per page is not the same thing as an unbounded crawl. Moved the
// boundedness assertion to Public URLs (the actual page-crawl-budget
// metric) instead, which is what "deep is not unlimited" is actually
// about; the deep-discovers-more-than-web comparison stays on
// EligibleTargets, still valid and still meaningful.
func TestScanCmd_DeepProfile_CrawlsMoreThanWeb_ButBounded(t *testing.T) {
	const totalPages = 30
	srv := chainPageServer(totalPages)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	_, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	// requests_per_second raised well above the (deliberately polite,
	// real-target-safe) 5.0 default: up to 75 eligible endpoints x 3
	// enabled-by-default detectors is real, legitimate detection work
	// this test wants to complete quickly against a local fixture --
	// still a bounded, explicit rate, just tuned for a fast test rather
	// than for being gentle with a real remote target.
	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\ndetection:\n  requests_per_second: 200.0\n", portStr))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", u.Hostname())

	webOut := c.mustRun("scan", u.Hostname(), "--profile", "web")
	webEligible := extractEligibleTargets(t, webOut)

	deepOut := c.mustRun("scan", u.Hostname(), "--profile", "deep")
	deepEligible := extractEligibleTargets(t, deepOut)
	deepPagesCrawled := extractPublicURLs(t, deepOut)

	if webEligible == 0 {
		t.Fatalf("web profile discovered 0 eligible targets against a fixture with %d pages -- fixture or crawler broken:\n%s", totalPages, webOut)
	}
	if deepEligible <= webEligible {
		t.Errorf("deep profile (eligible=%d) did not discover more than web (eligible=%d) against a %d-page fixture", deepEligible, webEligible, totalPages)
	}
	if deepPagesCrawled >= totalPages {
		t.Errorf("deep profile crawled %d pages out of %d total -- expected a BOUNDED subset, not everything (deep is not \"unlimited\")", deepPagesCrawled, totalPages)
	}
}

var (
	eligibleTargetsRe = regexp.MustCompile(`Eligible targets: (\d+)`)
	publicURLsRe      = regexp.MustCompile(`Public URLs:\s+(\d+)`)
)

func extractEligibleTargets(t *testing.T, out string) int {
	t.Helper()
	m := eligibleTargetsRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find \"Eligible targets: N\" in output:\n%s", out)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse eligible targets count: %v", err)
	}
	return n
}

// extractPublicURLs reads the Crawl: block's own "Public URLs: N"
// line -- the number of PAGES actually crawled (bounded by the
// profile's own MaxPages), independent of how many eligible
// detection TARGETS those pages go on to contribute (which scales
// with parameters per page, not with the size of the crawl itself --
// see this function's own caller for why that distinction matters).
func extractPublicURLs(t *testing.T, out string) int {
	t.Helper()
	m := publicURLsRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find \"Public URLs: N\" in output:\n%s", out)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse public URLs count: %v", err)
	}
	return n
}
