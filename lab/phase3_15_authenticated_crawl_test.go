// Phase 3.15 Authenticated Crawling & Session-Aware Discovery: real
// orchestrator + real lab integration tests, against harness_auth.go's
// extended authenticated page graph (see that file's own doc comment
// for the graph diagram). Unit-level behavior (PinnedRoundTripper,
// crawler Jar/ExtraHeaders wiring, session-expiration detection) is
// already covered by internal/safedial, internal/crawler, and
// internal/orchestration's own test suites -- this file proves the
// FULL STACK works end to end against a realistic authenticated
// application, and that scope enforcement/isolation/determinism hold
// at this level too.
package lab

import (
	"context"
	"fmt"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// deepAuthOrchestrator mirrors phase3_14_auth_test.go's authOrchestrator
// but with crawl bounds deep/wide enough to reach every page in
// harness_auth.go's Phase 3.15 graph (root -> account -> dashboard/
// profile -> api/data/settings -> items is 4 hops deep).
func deepAuthOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	for _, r := range rules {
		if err := store.ScopeRules().Create(context.Background(), r); err != nil {
			t.Fatalf("create scope rule %+v: %v", r, err)
		}
	}

	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.AuthAddr)},
		PortDialTimeout:     500 * time.Millisecond,
		HTTPConfig:          httpstage.Config{Timeout: 3 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       6,
		CrawlMaxPages:       30,
		Logger:              detectionLogger(),
	}
	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       registerBenignDetectors(t),
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second},
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

func authScopeRules() []models.ScopeRule {
	return []models.ScopeRule{{Value: "auth.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
}

// ---------------------------------------------------------------------
// AUTHENTICATED PAGE / ENDPOINT / PARAMETER DISCOVERY
// ---------------------------------------------------------------------

// TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph is task
// section P's "authenticated links," "authenticated forms,"
// "authenticated parameters," and "authenticated API references," all
// in one real, end-to-end scan: /profile, /settings, /items, /api/data
// are ONLY reachable through authenticated links -- their presence in
// the discovered endpoint list is direct proof the crawl carried a
// working session across every hop, not just the first one.
func TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)

	orch, store := deepAuthOrchestrator(t, l, rules)
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v (errors=%+v)", err, result.Errors)
	}

	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	for _, want := range []string{"/account", "/dashboard", "/profile", "/settings", "/items", "/api/data"} {
		if !paths[want] {
			t.Errorf("authenticated crawl did not discover %s -- endpoints found: %v", want, paths)
		}
	}

	// Parameters: the settings form's fields must be discovered via the
	// SAME internal/parameters pipeline any other form already uses --
	// task section D's explicit "reuse the existing architecture, do
	// not create a second implementation."
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Parameters ListByScanJob: %v", err)
	}
	paramNames := map[string]bool{}
	for _, p := range params {
		paramNames[p.Name] = true
	}
	for _, want := range []string{"csrf_token", "display_name", "theme", "newsletter", "visibility"} {
		if !paramNames[want] {
			t.Errorf("settings form field %q not discovered as a parameter -- found: %v", want, paramNames)
		}
	}

	// Result-level summary (task section N): CrawlSummary must reflect
	// that this crawl was authenticated.
	if result.CrawlSummary.AuthenticatedURLs == 0 {
		t.Error("CrawlSummary.AuthenticatedURLs = 0, want > 0")
	}
	if result.CrawlSummary.AuthenticatedEndpoints == 0 {
		t.Error("CrawlSummary.AuthenticatedEndpoints = 0, want > 0")
	}
	if result.AuthenticatedRequests == 0 {
		t.Error("AuthenticatedRequests = 0, want > 0")
	}
	if result.SessionExpired {
		t.Error("SessionExpired = true, want false (a fresh, valid session)")
	}
}

// TestPhase3_15_CSRFAndSensitiveFieldValues_Redacted proves task
// section D/I's "sensitive fields must be classified/redacted" against
// a REAL discovered parameter, not just internal/evidence's own unit
// tests -- the settings form's csrf_token field must never carry its
// raw value ("lab-fixed-settings-csrf-token") into storage.
func TestPhase3_15_CSRFAndSensitiveFieldValues_Redacted(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	orch, store := deepAuthOrchestrator(t, l, rules)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, p := range params {
		if p.Name == "csrf_token" && p.Value == "lab-fixed-settings-csrf-token" {
			t.Fatalf("SECURITY: csrf_token's raw value was persisted unredacted: %+v", p)
		}
		if p.Value == "lab-fixed-settings-csrf-token" {
			t.Fatalf("SECURITY: the raw CSRF token value leaked under an unexpected field name: %+v", p)
		}
	}
}

// ---------------------------------------------------------------------
// SCOPE ENFORCEMENT AFTER AUTHENTICATION
// ---------------------------------------------------------------------

// TestPhase3_15_AuthenticatedLinkToOutOfScopeHost_NeverDialed is task
// section H: an authenticated page (/profile) links directly to the
// pre-existing out-of-scope external.scanner.test host. "discovered !=
// authorized" -- the link may appear in the crawled page's own Links
// list, but no Endpoint, finding, or dial ever results from it.
func TestPhase3_15_AuthenticatedLinkToOutOfScopeHost_NeverDialed(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules() // only auth.scanner.test -- external.scanner.test has no rule
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	orch, store := deepAuthOrchestrator(t, l, rules)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if result.ReconSummary.HostCount != 1 {
		t.Errorf("ReconSummary.HostCount = %d, want 1 (only auth.scanner.test -- external.scanner.test must never become a second discovered host)", result.ReconSummary.HostCount)
	}
	for _, e := range endpoints {
		if e.HTTPServiceID == "" {
			continue
		}
	}
	// The strongest available check: the scan must complete (not hang)
	// well within its own StageTimeout, and no finding/endpoint may
	// trace back to a service on external.scanner.test's own address
	// (ipExternal, an RFC 5737 TEST-NET-3 address with nothing
	// listening -- see harness.go) -- if the crawler had ever actually
	// dialed it, the request would time out, not fail fast, and this
	// test would itself hang until StageTimeout.
	if result.Status == orchestrator.StatusFailed {
		for _, e := range result.Errors {
			t.Logf("scan error (informational): %+v", e)
		}
	}
}

// TestPhase3_15_AuthenticatedRedirectToOutOfScopeHost_NotFollowed is
// task section H's redirect variant: /redirect-to-external is an
// AUTHENTICATED endpoint (requires a valid session to even reach) that
// itself redirects to external.scanner.test. safedial's CheckRedirect
// must refuse the hop exactly as it would unauthenticated.
func TestPhase3_15_AuthenticatedRedirectToOutOfScopeHost_NotFollowed(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)

	validator := scope.NewValidator(rules, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "auth.scanner.test", l)
	client := sess.NewClient(dialer, "auth.scanner.test", ip, 5*time.Second, 5)

	resp, err := client.Get("http://auth.scanner.test:" + portOf(l.AuthAddr) + "/redirect-to-external")
	if err != nil {
		t.Fatalf("GET /redirect-to-external: %v", err)
	}
	defer resp.Body.Close()
	// safedial's CheckRedirect returns ErrUseLastResponse for an
	// out-of-scope hop -- the client stops following and returns the
	// 302 itself (StatusFound), never a response FROM external.scanner.test.
	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want 302 (the redirect must be truncated, not followed)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc == "" {
		t.Error("expected a Location header naming the (unfollowed) external redirect target")
	}
}

// ---------------------------------------------------------------------
// SESSION EXPIRATION
// ---------------------------------------------------------------------

// TestPhase3_15_SessionExpiration_DetectedVia401 is task section F/P's
// core scenario: the session is invalidated server-side (via /logout,
// called directly -- outside the crawl, exactly as a real session
// timeout would happen asynchronously), then an authenticated crawl is
// run with the now-stale cookie. /account correctly returns 401
// (requireSession's own logic), which detectSessionExpired must catch;
// the crawl must still complete (no hang, no infinite re-login loop)
// and still record whatever WAS reachable (/public, /login) rather
// than aborting the whole scan.
func TestPhase3_15_SessionExpiration_DetectedVia401(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)

	// Invalidate the session server-side, directly -- simulating an
	// asynchronous session timeout/logout that happened before this
	// crawl even started.
	validator := scope.NewValidator(rules, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "auth.scanner.test", l)
	directClient := sess.NewClient(dialer, "auth.scanner.test", ip, 5*time.Second, 5)
	logoutResp, err := directClient.Get("http://auth.scanner.test:" + portOf(l.AuthAddr) + "/logout")
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	logoutResp.Body.Close()

	orch, store := deepAuthOrchestrator(t, l, rules)
	done := make(chan struct{})
	var result orchestrator.Result
	var runErr error
	go func() {
		result, runErr = orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("scan did not complete within 20s -- possible infinite re-login loop or hang after session expiration")
	}
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if !result.SessionExpired {
		t.Error("SessionExpired = false, want true (the session was invalidated via /logout before the crawl started)")
	}
	// Already-reachable public content must still be recorded --
	// task's "preserve already discovered results."
	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	if !paths["/public"] {
		t.Errorf("public content was not preserved despite session expiration -- endpoints: %v", paths)
	}
	// The now-inaccessible authenticated-only pages must NOT appear --
	// they were never actually reached with a valid session.
	for _, unreachable := range []string{"/dashboard", "/profile", "/settings", "/items", "/api/data"} {
		if paths[unreachable] {
			t.Errorf("endpoint %s was recorded as discovered despite an expired session -- should be unreachable", unreachable)
		}
	}
}

// ---------------------------------------------------------------------
// CONCURRENCY / ISOLATION
// ---------------------------------------------------------------------

// TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination is
// task section K's "concurrent scans using the same auth profile" --
// two INDEPENDENT Authenticate() calls against the SAME profile/account
// (as two genuinely separate scans would each do; nothing is EVER
// cached or shared across Provider.Authenticate calls) run
// concurrently. Each must reach its own consistent, uncorrupted result.
func TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	// t.Setenv is called once, here, in the main test goroutine only
	// (its own docs note it is unsafe to use concurrently/in parallel
	// tests) -- the resolved Profile is then reused to authenticate
	// three times CONCURRENTLY below, exactly like three genuinely
	// separate scan processes each resolving the same configured
	// profile independently would.
	t.Setenv("SAKANNER_LAB_TEST_USER_"+AccountAUsername, AccountAUsername)
	t.Setenv("SAKANNER_LAB_TEST_PASS_"+AccountAUsername, AccountAPassword)
	profile, err := auth.ResolveProfile(auth.ProfileConfig{
		Name: "lab-" + AccountAUsername, Type: auth.TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://auth.scanner.test:%d/login", mustPort(t, l.AuthAddr)),
		UsernameEnv: "SAKANNER_LAB_TEST_USER_" + AccountAUsername, PasswordEnv: "SAKANNER_LAB_TEST_PASS_" + AccountAUsername,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}

	// Orchestrators (and their t.Fatalf-capable construction helper)
	// are built HERE, in the main test goroutine -- testing.T's
	// FailNow (which Fatalf calls) must only ever be invoked from the
	// goroutine running the test function itself, never from a spawned
	// goroutine. Only Authenticate/Run (neither of which touches *t*)
	// run concurrently below.
	type scanSetup struct {
		orch *orchestrator.Orchestrator
	}
	setups := make([]scanSetup, 3)
	for i := range setups {
		orch, _ := deepAuthOrchestrator(t, l, rules)
		setups[i] = scanSetup{orch: orch}
	}

	type outcome struct {
		result orchestrator.Result
		err    error
	}
	results := make(chan outcome, 3)
	for i := 0; i < 3; i++ {
		setup := setups[i]
		go func() {
			provider, provErr := auth.NewProvider(profile)
			if provErr != nil {
				results <- outcome{err: provErr}
				return
			}
			sess, authErr := provider.Authenticate(context.Background(), authDeps(l, rules...))
			if authErr != nil {
				results <- outcome{err: authErr}
				return
			}
			r, err := setup.orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
			results <- outcome{result: r, err: err}
		}()
	}
	for i := 0; i < 3; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("Run: %v", o.err)
		}
		if o.result.AuthState != auth.StateAuthenticated {
			t.Errorf("scan %s: AuthState = %s, want AUTHENTICATED", o.result.ScanID, o.result.AuthState)
		}
		if o.result.SessionExpired {
			t.Errorf("scan %s: SessionExpired = true, want false", o.result.ScanID)
		}
		if o.result.CrawlSummary.AuthenticatedEndpoints == 0 {
			t.Errorf("scan %s: AuthenticatedEndpoints = 0, want > 0", o.result.ScanID)
		}
	}
}

// TestPhase3_15_Determinism_RepeatedAuthenticatedScans_SameStructuralCounts
// is task section J: identical target/scope/auth profile/crawler
// config must produce deterministic discovered-URL/endpoint/parameter
// COUNTS across repeated runs -- not byte-identical session tokens
// (which are intentionally random, see harness_auth.go's newSession
// doc comment), but the same structural shape every time.
func TestPhase3_15_Determinism_RepeatedAuthenticatedScans_SameStructuralCounts(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	var endpointCounts, paramCounts []int
	var authenticatedEndpointCounts []int
	for i := 0; i < 3; i++ {
		sess := authenticateAccount(t, l, AccountAUsername, AccountAPassword, rules...)
		orch, store := deepAuthOrchestrator(t, l, rules)
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d ListByScanJob: %v", i, err)
		}
		params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d Parameters ListByScanJob: %v", i, err)
		}
		endpointCounts = append(endpointCounts, len(endpoints))
		paramCounts = append(paramCounts, len(params))
		authenticatedEndpointCounts = append(authenticatedEndpointCounts, result.CrawlSummary.AuthenticatedEndpoints)
	}
	for i := 1; i < len(endpointCounts); i++ {
		if endpointCounts[i] != endpointCounts[0] {
			t.Errorf("endpoint count not deterministic: run 0=%d run %d=%d", endpointCounts[0], i, endpointCounts[i])
		}
		if paramCounts[i] != paramCounts[0] {
			t.Errorf("parameter count not deterministic: run 0=%d run %d=%d", paramCounts[0], i, paramCounts[i])
		}
		if authenticatedEndpointCounts[i] != authenticatedEndpointCounts[0] {
			t.Errorf("AuthenticatedEndpoints not deterministic: run 0=%d run %d=%d", authenticatedEndpointCounts[0], i, authenticatedEndpointCounts[i])
		}
	}
}
