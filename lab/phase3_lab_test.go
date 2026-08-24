// Phase 3 Security Test Laboratory integration tests.
//
// These tests verify the LAB (fixtures, ground truth, comparison
// machinery) works -- they do NOT test, simulate, or claim any
// vulnerability-detection capability themselves. As of Phase 3.2 one
// real detector exists (internal/detectors/xssreflected, see
// phase3_2_reflected_xss_test.go for ITS integration tests), but
// nothing in THIS file ever constructs or runs a detection.Engine.
// Wherever a test below runs the real scanner (orchestration.Pipeline)
// and looks at Findings, it is proving the integration point works end
// to end with the CURRENT, correct answer for a recon-only run (zero
// findings, since detection was never invoked) -- not faking a future
// result.
package lab

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/orchestration"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func testVulnLab(t *testing.T) *Lab {
	t.Helper()
	gt, err := LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	l, err := StartWithVulnerabilities(gt)
	if err != nil {
		t.Fatalf("StartWithVulnerabilities: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

// --- Health: every fixture endpoint responds, positive and negative ---

// TestPhase3Lab_AllFixturesReachable is the lab's basic health check:
// every endpoint named in ground-truth-vulnerabilities.yaml responds
// without hanging, panicking, or connection-refusing.
func TestPhase3Lab_AllFixturesReachable(t *testing.T) {
	l := testVulnLab(t)
	vulnGT, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}

	base := "http://" + l.VulnAddr
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	get := func(path string) (int, error) {
		u := base + path
		if !strings.Contains(path, "?") {
			// A handful of endpoints take path parameters (e.g.
			// /idor/vulnerable/user/{id}) -- ground truth documents the
			// template, substitute a concrete id for reachability.
			u = strings.ReplaceAll(u, "{id}", "1")
		}
		resp, err := client.Get(u)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	for _, f := range vulnGT.Findings {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			endpoint := strings.ReplaceAll(f.Endpoint, "{id}", "1")
			status, err := get(endpoint)
			if err != nil {
				t.Fatalf("GET %s: %v", endpoint, err)
			}
			if status == 0 {
				t.Errorf("GET %s: got status 0", endpoint)
			}
		})
	}

	// The index page itself, and the SSRF-internal fixture.
	if status, err := get("/"); err != nil || status != 200 {
		t.Errorf("index page: status=%d err=%v", status, err)
	}
	resp, err := http.Get("http://" + l.SSRFInternalAddr + "/")
	if err != nil {
		t.Fatalf("ssrf-internal fixture unreachable: %v", err)
	}
	resp.Body.Close()
}

// --- Positive fixtures actually exhibit the documented vulnerability ---

// TestPhase3Lab_PositiveFixturesExhibitVulnerability drives each
// positive fixture with its documented probe payload and confirms the
// documented behavior actually happens -- proving the vulnerability is
// real application behavior, not an assertion made up in YAML with
// nothing backing it.
func TestPhase3Lab_PositiveFixturesExhibitVulnerability(t *testing.T) {
	l := testVulnLab(t)
	base := "http://" + l.VulnAddr

	t.Run("reflected_xss", func(t *testing.T) {
		body := mustGetBody(t, base+"/xss/reflected/vulnerable?"+url.Values{"q": {"<script>sakannerXSSPROBE</script>"}}.Encode())
		if !strings.Contains(body, "<script>sakannerXSSPROBE</script>") {
			t.Errorf("payload not reflected unescaped: %s", body)
		}
	})

	t.Run("reflected_xss_attribute", func(t *testing.T) {
		payload := `<sakannerXSSPROBE>"'`
		body := mustGetBody(t, base+"/xss/reflected/attribute/vulnerable?"+url.Values{"name": {payload}}.Encode())
		if !strings.Contains(body, payload) {
			t.Errorf("payload not reflected unescaped in the attribute: %s", body)
		}
	})

	t.Run("stored_xss", func(t *testing.T) {
		mustPostForm(t, base+"/xss/stored/vulnerable", url.Values{"comment": {"<script>sakannerXSSPROBE</script>"}})
		body := mustGetBody(t, base+"/xss/stored/vulnerable")
		if !strings.Contains(body, "<script>sakannerXSSPROBE</script>") {
			t.Errorf("stored payload not reflected unescaped on a later GET: %s", body)
		}
	})

	t.Run("sql_injection_boolean", func(t *testing.T) {
		body := mustGetBody(t, base+"/sqli/vulnerable?"+url.Values{"id": {"' OR '1'='1"}}.Encode())
		if !strings.Contains(body, "alice") || !strings.Contains(body, "bob") || !strings.Contains(body, "admin") {
			t.Errorf("tautology payload did not return all rows: %s", body)
		}
	})

	t.Run("sql_injection_error_based", func(t *testing.T) {
		resp, err := http.Get(base + "/sqli/vulnerable?" + url.Values{"id": {"'"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 500 {
			t.Errorf("status = %d, want 500 for a bare-quote error-based probe", resp.StatusCode)
		}
	})

	t.Run("sql_injection_boolean_only_no_error", func(t *testing.T) {
		trueBody := mustGetBody(t, base+"/sqli/boolean/vulnerable?"+url.Values{"id": {"1' OR '1'='1"}}.Encode())
		if !strings.Contains(trueBody, "alice") || !strings.Contains(trueBody, "bob") || !strings.Contains(trueBody, "admin") {
			t.Errorf("true-condition payload did not return all rows: %s", trueBody)
		}
		falseBody := mustGetBody(t, base+"/sqli/boolean/vulnerable?"+url.Values{"id": {"1' AND '1'='2"}}.Encode())
		if falseBody != "results: (none)" {
			t.Errorf("false-condition payload = %q, want \"results: (none)\"", falseBody)
		}
		resp, err := http.Get(base + "/sqli/boolean/vulnerable?" + url.Values{"id": {"'"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200 -- this fixture must never surface a database error", resp.StatusCode)
		}
	})

	t.Run("authentication_weakness", func(t *testing.T) {
		body := mustGetBody(t, base+"/auth/weak-credentials?"+url.Values{"username": {"admin"}, "password": {"admin"}}.Encode())
		if !strings.Contains(body, "login successful") {
			t.Errorf("default credentials were not accepted: %s", body)
		}
	})

	t.Run("idor", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/idor/vulnerable/user/2", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: "user1"}) // a DIFFERENT user's session
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200 (returns another user's data regardless of session)", resp.StatusCode)
		}
	})

	t.Run("path_traversal", func(t *testing.T) {
		body := mustGetBody(t, base+"/files/traversal/vulnerable?"+url.Values{"name": {"../../../etc/passwd"}}.Encode())
		if !strings.Contains(body, "sakanner-lab-synthetic-fixture-file") {
			t.Errorf("traversal-shaped input did not reach the synthetic fixture content: %s", body)
		}
	})

	t.Run("local_file_inclusion", func(t *testing.T) {
		body := mustGetBody(t, base+"/files/lfi/vulnerable?"+url.Values{"page": {"../../../etc/passwd"}}.Encode())
		if !strings.Contains(body, "sakanner-lab-synthetic-fixture-file") {
			t.Errorf("traversal-shaped page parameter did not reach synthetic fixture content: %s", body)
		}
	})

	t.Run("ssrf", func(t *testing.T) {
		target := "http://" + l.SSRFInternalAddr + "/"
		body := mustGetBody(t, base+"/ssrf/vulnerable?"+url.Values{"url": {target}}.Encode())
		if !strings.Contains(body, "ssrf-internal-fixture") {
			t.Errorf("fixture did not fetch and reflect the internal service's response: %s", body)
		}
	})

	t.Run("open_redirect", func(t *testing.T) {
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(base + "/redirect/open/vulnerable?" + url.Values{"next": {"http://external.scanner.test/"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "http://external.scanner.test/" {
			t.Errorf("Location = %q, want the unvalidated next parameter echoed verbatim", loc)
		}
	})

	t.Run("verbose_error", func(t *testing.T) {
		body := mustGetBody(t, base+"/misconfig/stacktrace/vulnerable")
		if !strings.Contains(body, "Traceback") {
			t.Errorf("no stack-trace-shaped content in response: %s", body)
		}
	})

	t.Run("sensitive_information_exposure", func(t *testing.T) {
		body := mustGetBody(t, base+"/info/exposure/vulnerable")
		if !strings.Contains(body, "api_key=sk_test_SAKANNER_LAB_FIXTURE") {
			t.Errorf("no credential-shaped string in response: %s", body)
		}
	})

	t.Run("insecure_cookie", func(t *testing.T) {
		resp, err := http.Get(base + "/cookies/insecure/vulnerable")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		cookie := resp.Header.Get("Set-Cookie")
		for _, attr := range []string{"HttpOnly", "Secure", "SameSite"} {
			if strings.Contains(cookie, attr) {
				t.Errorf("Set-Cookie unexpectedly contains %s: %s", attr, cookie)
			}
		}
	})

	t.Run("cors_misconfiguration", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/cors/vulnerable", nil)
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://evil.example" {
			t.Errorf("Access-Control-Allow-Origin = %q, want the arbitrary Origin reflected back", got)
		}
		if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("Access-Control-Allow-Credentials missing or not true")
		}
	})

	t.Run("missing_security_headers", func(t *testing.T) {
		resp, err := http.Get(base + "/headers/missing/vulnerable")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"} {
			if resp.Header.Get(h) != "" {
				t.Errorf("header %s unexpectedly present", h)
			}
		}
	})

	t.Run("vulnerable_component", func(t *testing.T) {
		body := mustGetBody(t, base+"/component/old-jquery.js")
		if !strings.Contains(body, "jQuery v1.6.1") {
			t.Errorf("old-jquery.js does not serve the expected old version banner: %s", body)
		}
	})

	t.Run("exposed_admin", func(t *testing.T) {
		body := mustGetBody(t, base+"/admin/exposed")
		if !strings.Contains(body, "Admin Panel") {
			t.Errorf("admin panel not reachable without authentication: %s", body)
		}
	})

	t.Run("directory_listing", func(t *testing.T) {
		body := mustGetBody(t, base+"/directory-listing/vulnerable/")
		if !strings.Contains(body, "Index of /uploads") {
			t.Errorf("no directory-listing-shaped content: %s", body)
		}
	})
}

// --- Negative fixtures do NOT exhibit the vulnerability (false-positive check) ---

// TestPhase3Lab_NegativeFixturesDoNotExhibitVulnerability drives every
// safe counterpart with the SAME probe payloads used against the
// vulnerable fixtures above, and confirms the vulnerability pattern does
// not appear. This is what a future Phase 3 detector's false-positive
// rate will be measured against.
func TestPhase3Lab_NegativeFixturesDoNotExhibitVulnerability(t *testing.T) {
	l := testVulnLab(t)
	base := "http://" + l.VulnAddr

	t.Run("reflected_xss_safe", func(t *testing.T) {
		body := mustGetBody(t, base+"/xss/reflected/safe?"+url.Values{"q": {"<script>sakannerXSSPROBE</script>"}}.Encode())
		if strings.Contains(body, "<script>sakannerXSSPROBE</script>") {
			t.Errorf("EXPECTED no vulnerability, but the payload was reflected unescaped: %s", body)
		}
	})

	t.Run("reflected_xss_attribute_safe", func(t *testing.T) {
		payload := `<sakannerXSSPROBE>"'`
		body := mustGetBody(t, base+"/xss/reflected/attribute/safe?"+url.Values{"name": {payload}}.Encode())
		if strings.Contains(body, payload) {
			t.Errorf("EXPECTED no vulnerability, but the payload was reflected unescaped in the attribute: %s", body)
		}
	})

	t.Run("reflected_xss_unrelated", func(t *testing.T) {
		body := mustGetBody(t, base+"/xss/reflected/unrelated?"+url.Values{"q": {"sakannerXSSPROBE"}}.Encode())
		if strings.Contains(body, "sakannerXSSPROBE") {
			t.Errorf("EXPECTED the parameter to never be reflected, but found the marker: %s", body)
		}
	})

	t.Run("reflected_xss_static_decoy", func(t *testing.T) {
		body := mustGetBody(t, base+"/xss/reflected/static-decoy?"+url.Values{"q": {"sakannerXSSPROBE"}}.Encode())
		if strings.Contains(body, "sakannerXSSPROBE") {
			t.Errorf("EXPECTED the parameter to never be reflected, but found the marker: %s", body)
		}
		if !strings.Contains(body, "<script>legacyExampleWidget()</script>") {
			t.Errorf("EXPECTED the static decoy content to always be present regardless of the parameter: %s", body)
		}
	})

	t.Run("stored_xss_safe", func(t *testing.T) {
		mustPostForm(t, base+"/xss/stored/safe", url.Values{"comment": {"<script>sakannerXSSPROBE</script>"}})
		body := mustGetBody(t, base+"/xss/stored/safe")
		if strings.Contains(body, "<script>sakannerXSSPROBE</script>") {
			t.Errorf("EXPECTED no vulnerability, but the stored payload was reflected unescaped: %s", body)
		}
	})

	t.Run("sql_injection_safe", func(t *testing.T) {
		body := mustGetBody(t, base+"/sqli/safe?"+url.Values{"id": {"' OR '1'='1"}}.Encode())
		if strings.Contains(body, "alice") && strings.Contains(body, "bob") {
			t.Errorf("EXPECTED no vulnerability, but the tautology payload returned all rows: %s", body)
		}
	})

	t.Run("sql_injection_boolean_safe", func(t *testing.T) {
		trueBody := mustGetBody(t, base+"/sqli/boolean/safe?"+url.Values{"id": {"1' OR '1'='1"}}.Encode())
		falseBody := mustGetBody(t, base+"/sqli/boolean/safe?"+url.Values{"id": {"1' AND '1'='2"}}.Encode())
		if trueBody != falseBody {
			t.Errorf("EXPECTED identical behavior regardless of condition, got true=%q false=%q", trueBody, falseBody)
		}
	})

	t.Run("sql_injection_generic_error", func(t *testing.T) {
		baseline := mustGetBody(t, base+"/sqli/generic-error?"+url.Values{"id": {"1"}}.Encode())
		probe := mustGetBody(t, base+"/sqli/generic-error?"+url.Values{"id": {"'"}}.Encode())
		if baseline != probe {
			t.Errorf("EXPECTED identical generic error regardless of input, got baseline=%q probe=%q", baseline, probe)
		}
	})

	t.Run("sql_injection_dynamic_content_varies", func(t *testing.T) {
		b1 := mustGetBody(t, base+"/sqli/dynamic?"+url.Values{"id": {"1"}}.Encode())
		b2 := mustGetBody(t, base+"/sqli/dynamic?"+url.Values{"id": {"1' OR '1'='1"}}.Encode())
		if b1 == b2 {
			t.Error("EXPECTED the raw response to vary request-to-request regardless of parameter (this is the fixture's whole point -- it exercises response normalization elsewhere, not raw equality)")
		}
		if !strings.HasPrefix(b1, "results: (none)") || !strings.HasPrefix(b2, "results: (none)") {
			t.Errorf("EXPECTED the meaningful content to always be \"results: (none)\", got %q and %q", b1, b2)
		}
	})

	t.Run("ssrf_reflect_only", func(t *testing.T) {
		body := mustGetBody(t, base+"/ssrf/reflect-only?"+url.Values{"url": {"http://127.0.0.23/cb/raw-check-only"}}.Encode())
		if !strings.Contains(body, "127.0.0.23") {
			t.Errorf("EXPECTED the url to be reflected verbatim (this fixture's whole point): %s", body)
		}
	})

	t.Run("ssrf_store_only", func(t *testing.T) {
		body := mustGetBody(t, base+"/ssrf/store-only?"+url.Values{"url": {"http://127.0.0.23/cb/raw-check-only"}}.Encode())
		if body != "saved" {
			t.Errorf("body = %q, want \"saved\"", body)
		}
	})

	t.Run("ssrf_client_fetch_only", func(t *testing.T) {
		body := mustGetBody(t, base+"/ssrf/client-fetch?"+url.Values{"url": {"http://127.0.0.23/cb/raw-check-only"}}.Encode())
		if !strings.Contains(body, `<img src="http://127.0.0.23/cb/raw-check-only"`) {
			t.Errorf("EXPECTED the url embedded in an <img> tag: %s", body)
		}
	})

	t.Run("ssrf_validate_reject", func(t *testing.T) {
		resp, err := http.Get(base + "/ssrf/validate-reject?" + url.Values{"url": {"http://127.0.0.23/cb/raw-check-only"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("status = %d, want 400 -- a non-partner destination must always be rejected", resp.StatusCode)
		}
	})

	t.Run("authentication_weakness_safe", func(t *testing.T) {
		body := mustGetBody(t, base+"/auth/strong-credentials?"+url.Values{"username": {"admin"}, "password": {"admin"}}.Encode())
		if strings.Contains(body, "login successful") {
			t.Error("EXPECTED no vulnerability, but the default credential pair was accepted")
		}
	})

	t.Run("idor_safe", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/idor/safe/user/2", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: "user1"}) // a DIFFERENT user's session
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Error("EXPECTED no vulnerability, but a mismatched session was allowed to read another user's data")
		}
	})

	t.Run("path_traversal_safe", func(t *testing.T) {
		resp, err := http.Get(base + "/files/traversal/safe?" + url.Values{"name": {"../../../etc/passwd"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Error("EXPECTED no vulnerability, but a traversal-shaped name returned 200")
		}
	})

	t.Run("open_redirect_safe", func(t *testing.T) {
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(base + "/redirect/open/safe?" + url.Values{"next": {"http://external.scanner.test/"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc == "http://external.scanner.test/" {
			t.Errorf("EXPECTED no vulnerability, but the unvalidated destination was echoed: %s", loc)
		}
	})

	t.Run("insecure_cookie_safe", func(t *testing.T) {
		resp, err := http.Get(base + "/cookies/insecure/safe")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		cookie := resp.Header.Get("Set-Cookie")
		for _, attr := range []string{"HttpOnly", "Secure", "SameSite"} {
			if !strings.Contains(cookie, attr) {
				t.Errorf("EXPECTED all protective attributes present, missing %s: %s", attr, cookie)
			}
		}
	})

	t.Run("cors_safe", func(t *testing.T) {
		req, _ := http.NewRequest("GET", base+"/cors/safe", nil)
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "https://evil.example" {
			t.Error("EXPECTED no vulnerability, but an arbitrary Origin was reflected")
		}
	})

	t.Run("missing_headers_safe", func(t *testing.T) {
		resp, err := http.Get(base + "/headers/missing/safe")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, h := range []string{"Content-Security-Policy", "X-Frame-Options"} {
			if resp.Header.Get(h) == "" {
				t.Errorf("EXPECTED header %s present, it was not", h)
			}
		}
	})
}

// --- SSRF fixture isolation ---------------------------------------------

// TestPhase3Lab_SSRFFixtureIsolated proves the SSRF-vulnerable fixture
// can reach the lab-internal service (the vulnerability is real) but
// structurally cannot reach anything outside 127.0.0.0/8 (the lab's own
// safety net) -- see docs/phase-3-test-lab.md "SSRF fixture isolation".
func TestPhase3Lab_SSRFFixtureIsolated(t *testing.T) {
	l := testVulnLab(t)
	base := "http://" + l.VulnAddr

	t.Run("reaches_internal_service", func(t *testing.T) {
		target := "http://" + l.SSRFInternalAddr + "/"
		body := mustGetBody(t, base+"/ssrf/vulnerable?"+url.Values{"url": {target}}.Encode())
		if !strings.Contains(body, "ssrf-internal-fixture") {
			t.Errorf("expected to reach the internal fixture, got: %s", body)
		}
	})

	t.Run("refuses_non_loopback_destination", func(t *testing.T) {
		// 203.0.113.99 is external.scanner.test's real (RFC 5737,
		// non-routable) address -- not loopback, so the fixture's own
		// safety net must refuse it before ever attempting the fetch.
		resp, err := http.Get(base + "/ssrf/vulnerable?" + url.Values{"url": {"http://203.0.113.99/"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 502 {
			t.Errorf("status = %d, want 502 (fixture safety net refusal)", resp.StatusCode)
		}
	})

	t.Run("refuses_domain_name_destination", func(t *testing.T) {
		// Even a destination that RESOLVES to loopback via hostname is
		// refused, since the fixture only accepts a literal IP -- it
		// never performs its own DNS resolution at all, so there is no
		// path through this fixture that could ever reach a real
		// external host by name.
		resp, err := http.Get(base + "/ssrf/vulnerable?" + url.Values{"url": {"http://example.com/"}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 502 {
			t.Errorf("status = %d, want 502", resp.StatusCode)
		}
	})
}

// --- Determinism -----------------------------------------------------------

// TestPhase3Lab_Determinism runs the same probe against two entirely
// separate Lab instances (fresh Start/Close cycles, as two different
// test runs would each get) and confirms byte-identical results -- no
// randomness, no shared state leaking between runs.
func TestPhase3Lab_Determinism(t *testing.T) {
	// Each lab instance is closed explicitly and immediately, rather than
	// via t.Cleanup (which would defer every Close to the very end of
	// this test function, in LIFO order) -- altport.scanner.test binds a
	// FIXED port (not OS-assigned), so a second Start before the first
	// Lab's Close actually runs would fail with "address already in
	// use". Starting and fully stopping one lab before starting the next
	// is also a more faithful simulation of "two separate test runs"
	// than several labs running concurrently would be.
	run := func() string {
		gt, err := LoadGroundTruth()
		if err != nil {
			t.Fatalf("LoadGroundTruth: %v", err)
		}
		l, err := StartWithVulnerabilities(gt)
		if err != nil {
			t.Fatalf("StartWithVulnerabilities: %v", err)
		}
		defer l.Close()
		return mustGetBody(t, "http://"+l.VulnAddr+"/xss/reflected/vulnerable?q=determinism-check")
	}
	first := run()
	second := run()
	if first != second {
		t.Errorf("two separate lab runs produced different output:\nfirst:  %q\nsecond: %q", first, second)
	}

	// Stored XSS specifically: a fresh lab must never see a previous
	// lab's stored data (closure-scoped state, not a package global --
	// see harness_vuln.go's registerStoredXSS comment).
	storedBodyFromFreshLab := func() string {
		gt, err := LoadGroundTruth()
		if err != nil {
			t.Fatalf("LoadGroundTruth: %v", err)
		}
		l, err := StartWithVulnerabilities(gt)
		if err != nil {
			t.Fatalf("StartWithVulnerabilities: %v", err)
		}
		defer l.Close()
		return mustGetBody(t, "http://"+l.VulnAddr+"/xss/stored/vulnerable")
	}

	func() {
		gt, err := LoadGroundTruth()
		if err != nil {
			t.Fatalf("LoadGroundTruth: %v", err)
		}
		l1, err := StartWithVulnerabilities(gt)
		if err != nil {
			t.Fatalf("StartWithVulnerabilities: %v", err)
		}
		defer l1.Close()
		mustPostForm(t, "http://"+l1.VulnAddr+"/xss/stored/vulnerable", url.Values{"comment": {"lab-one-comment"}})
	}()

	body := storedBodyFromFreshLab()
	if strings.Contains(body, "lab-one-comment") {
		t.Error("a fresh Lab instance saw stored state from a previous, unrelated Lab instance -- state is not properly isolated")
	}
}

// --- Scope enforcement, extended for the vulnerable fixtures ------------

// TestPhase3Lab_CrawlerNeverFollowsOutOfScopeLinkFromVulnApp runs a real
// scan (crawling enabled) against vuln.scanner.test and confirms the
// out-of-scope link on its index page is never followed -- the same
// property the Phase 2 lab already proves for scanner.test, re-confirmed
// here specifically for the Phase 3 fixture app, since it's a distinct
// codepath (a different host, a different page).
func TestPhase3Lab_CrawlerNeverFollowsOutOfScopeLinkFromVulnApp(t *testing.T) {
	l := testVulnLab(t)
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	targetID := uuid.NewString()
	if err := store.Targets().Create(ctx, models.Target{ID: targetID, Value: "vuln.scanner.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := store.ScopeRules().Create(ctx, models.ScopeRule{ID: uuid.NewString(), Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	p := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.VulnAddr)},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 4, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       30,
		Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
	}

	job, err := p.Run(ctx, orchestration.RunOptions{TargetIDs: []string{targetID}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	assets, err := store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Assets().ListByScanJob: %v", err)
	}
	for _, a := range assets {
		if a.Name == "external.scanner.test" {
			t.Fatalf("external.scanner.test was scanned -- scope bypass via a link on the vulnerable app's index page")
		}
	}
}

// TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated exercises the
// open-redirect fixture's own natural exploitation path (redirecting to
// an out-of-scope host) directly through sakanner's real dialer
// (internal/safedial), the same pattern the Phase 2 lab already
// established in redirect_test.go for redirect.scanner.test.
func TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated(t *testing.T) {
	l := testVulnLab(t)

	validator := scope.NewValidator([]models.ScopeRule{
		{ID: "r1", Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()},
	}, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "vuln.scanner.test", l)

	var chain []models.RedirectHop
	client := dialer.NewClient("vuln.scanner.test", ip, nil, &chain, 5*time.Second, 3)
	resp, err := client.Get(fmt.Sprintf("http://vuln.scanner.test:%s/redirect/open/vulnerable?next=http://external.scanner.test/", portOf(l.VulnAddr)))
	if err != nil {
		t.Fatalf("GET: %v (a dial to the out-of-scope host should never happen, let alone fail)", err)
	}
	defer resp.Body.Close()

	if resp.Request.URL.Hostname() == "external.scanner.test" {
		t.Fatal("the final response came from external.scanner.test -- the open-redirect fixture's natural exploitation path escaped scope enforcement")
	}
}

// --- Integration test foundation: scan + compare against ground truth ---

// TestPhase3Lab_ScanAndCompareAgainstGroundTruth is the integration
// point this whole file exists to prepare: start the lab, run a REAL
// scan with the REAL production pipeline against vuln.scanner.test,
// retrieve whatever Findings a real scan produces, and run
// CompareFindings against this lab's ground truth.
//
// As of this commit, sakanner has NO vulnerability detector -- nothing
// anywhere populates the Findings table. The correct, honest result of
// this test today is therefore: 0 actual findings, every positive
// ground-truth fixture reported as a false negative, 0 true positives,
// 0 false positives, 0 duplicates. That is exactly what this test
// asserts. It is not a placeholder and it is not disabled -- it is
// proof the comparison pipeline (real Store -> real Findings query ->
// CompareFindings -> classified report) works end to end, today, with
// today's true answer. The moment a real detector exists and starts
// writing to the Findings table, this same test, completely unchanged,
// will begin reporting real true/false positive and negative counts.
func TestPhase3Lab_ScanAndCompareAgainstGroundTruth(t *testing.T) {
	l := testVulnLab(t)
	vulnGT, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	targetID := uuid.NewString()
	if err := store.Targets().Create(ctx, models.Target{ID: targetID, Value: "vuln.scanner.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := store.ScopeRules().Create(ctx, models.ScopeRule{ID: uuid.NewString(), Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	p := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.VulnAddr)},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 4, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       30,
		Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
	}

	job, err := p.Run(ctx, orchestration.RunOptions{TargetIDs: []string{targetID}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	actualFindings, err := store.Findings().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Findings().ListByScanJob: %v", err)
	}

	report := CompareFindings(actualFindings, vulnGT.Positives(), vulnGT.Negatives())

	t.Logf("Phase 3 ground-truth comparison (this test runs RECON only, never internal/detection.Engine -- see this test's doc comment):")
	t.Logf("  expected: %d", report.TotalExpected)
	t.Logf("  actual:   %d", report.TotalActual)
	t.Logf("  true positives:  %d", report.TruePositives)
	t.Logf("  false positives: %d", report.FalsePositives)
	t.Logf("  false negatives: %d", report.FalseNegatives)
	t.Logf("  duplicates:      %d", report.Duplicates)

	if report.TotalActual != 0 {
		t.Errorf("TotalActual = %d, want 0 -- this test never invokes detection.Engine (see runReconAgainstVulnLab-style tests in phase3_1_detection_test.go / phase3_2_reflected_xss_test.go for that), so a recon-only run must not have produced any Findings rows", report.TotalActual)
	}
	if report.TotalExpected != 24 {
		t.Errorf("TotalExpected = %d, want 24 (17 vulnerability classes + 1 Phase 3.2 attribute-context reflected XSS + 1 Phase 3.3 boolean-only SQLi + 1 Phase 3.5 query-parameter IDOR + 1 Phase 3.6 query-parameter path traversal + 1 Phase 3.7 command injection + 1 Phase 3.25 blind/OOB-only SSRF + 1 Phase 3.26 Windows-cmd.exe-style command injection)", report.TotalExpected)
	}
	if report.FalseNegatives != report.TotalExpected {
		t.Errorf("FalseNegatives = %d, want %d (every expected finding, since nothing was found)", report.FalseNegatives, report.TotalExpected)
	}
	if report.TruePositives != 0 || report.FalsePositives != 0 || report.Duplicates != 0 {
		t.Errorf("expected 0 TP/FP/Duplicate with no detector, got TP=%d FP=%d Dup=%d", report.TruePositives, report.FalsePositives, report.Duplicates)
	}
}

// --- small helpers ---------------------------------------------------------

func mustGetBody(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		t.Fatalf("read body from %s: %v", u, err)
	}
	return string(b)
}

func mustPostForm(t *testing.T, u string, form url.Values) {
	t.Helper()
	resp, err := http.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	resp.Body.Close()
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return port
}
