package lab

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// TestLab_RedirectAndStatusScenarios exercises sakanner's real
// production dialer (internal/safedial, the exact same code
// internal/http.Prober and internal/crawler use) directly against
// redirect.scanner.test's sub-paths.
//
// This is necessary, not a shortcut: Prober.Probe and the crawler's
// start page both always fetch "/" only (see docs/phase-2-test-lab.md
// "Known limitations"), so /multi, /loop, /external-redirect, and the
// plain status-code paths are never reached by scanning redirect.scanner.test
// as an ordinary pipeline target. Pointing the same dialer at these
// paths directly is the most faithful way to verify their behavior
// without inventing a parallel implementation.
func TestLab_RedirectAndStatusScenarios(t *testing.T) {
	l := testLab(t)

	// Only redirect.scanner.test is in scope; external.scanner.test
	// deliberately has no rule, so the /external-redirect scenario is a
	// real test of the deny-by-default path, not a rule that happens to
	// be absent by coincidence.
	validator := scope.NewValidator([]models.ScopeRule{
		{ID: "r1", Value: "redirect.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()},
	}, true) // AllowReservedRanges: redirect.scanner.test is on 127.0.0.0/8

	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "redirect.scanner.test", l)
	svcGT := l.GT.Services["redirect.scanner.test"]

	get := func(path string) *http.Response {
		t.Helper()
		var chain []models.RedirectHop
		client := dialer.NewClient("redirect.scanner.test", ip, nil, &chain, 5*time.Second, 3)
		resp, err := client.Get(fmt.Sprintf("http://redirect.scanner.test:%s%s", portOf(l.RedirectHTTPAddr), path))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	for _, rd := range svcGT.Redirects {
		rd := rd
		t.Run(rd.Description, func(t *testing.T) {
			resp := get(rd.Path)
			switch {
			case rd.ExpectFinalScheme != "":
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200 (after following redirect)", resp.StatusCode)
				}
				if resp.Request.URL.Scheme != rd.ExpectFinalScheme {
					t.Errorf("final scheme = %q, want %q", resp.Request.URL.Scheme, rd.ExpectFinalScheme)
				}
			case rd.ExpectFinalPath != "":
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200 (after following redirect chain)", resp.StatusCode)
				}
				if resp.Request.URL.Path != rd.ExpectFinalPath {
					t.Errorf("final path = %q, want %q", resp.Request.URL.Path, rd.ExpectFinalPath)
				}
			case rd.ExpectTruncated:
				// A truncated chain returns the last response actually
				// received over the wire (a redirect itself), not a 200 --
				// see safedial.Dialer.NewClient's CheckRedirect.
				if resp.StatusCode != http.StatusFound {
					t.Errorf("status = %d, want 302 (chain truncated, not followed to completion)", resp.StatusCode)
				}
			}
		})
	}

	for _, sc := range svcGT.StatusCodes {
		sc := sc
		t.Run(sc.Path, func(t *testing.T) {
			resp := get(sc.Path)
			if resp.StatusCode != sc.ExpectStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, sc.ExpectStatus)
			}
		})
	}
}

// TestLab_ExternalRedirectNeverDialsOutOfScopeHost proves the
// /external-redirect truncation above isn't merely returning the right
// status code by coincidence -- external.scanner.test's own port must
// never actually receive a connection. Since external.scanner.test has
// no listener at all in this lab (only DNS resolves it -- see
// harness.go), the strongest evidence available is that safedial.Dialer
// returns cleanly rather than erroring out trying to reach it.
func TestLab_ExternalRedirectNeverDialsOutOfScopeHost(t *testing.T) {
	l := testLab(t)

	validator := scope.NewValidator([]models.ScopeRule{
		{ID: "r1", Value: "redirect.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()},
	}, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "redirect.scanner.test", l)

	var chain []models.RedirectHop
	client := dialer.NewClient("redirect.scanner.test", ip, nil, &chain, 5*time.Second, 3)
	resp, err := client.Get(fmt.Sprintf("http://redirect.scanner.test:%s/external-redirect", portOf(l.RedirectHTTPAddr)))
	if err != nil {
		t.Fatalf("GET /external-redirect: %v (a dial attempt to the out-of-scope host should never even happen, let alone fail)", err)
	}
	defer resp.Body.Close()

	if resp.Request.URL.Hostname() == "external.scanner.test" {
		t.Fatal("the final response came from external.scanner.test -- it was dialed despite having no scope rule")
	}
	if len(chain) == 0 || chain[len(chain)-1].StatusCode != http.StatusFound {
		t.Errorf("chain = %+v, want the last recorded hop to be the 302 that was refused, not followed", chain)
	}
}
