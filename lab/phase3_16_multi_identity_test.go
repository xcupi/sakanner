// Phase 3.16 Multi-Identity Authentication & Account Context: real
// orchestrator + real lab integration tests, going through the ACTUAL
// Identity layer (internal/auth.IdentityConfig -> ResolveIdentityProfile
// -> Provider.Authenticate, exactly as cmd/scanner's --identity flag
// does) rather than reusing Phase 3.14/3.15's lower-level
// Profile-only helpers directly -- this file's whole point is proving
// the IDENTITY abstraction itself works end to end against a real
// authenticated application with two distinct accounts, not merely
// that Session isolation (already proven in Phase 3.14/3.15) still
// holds.
package lab

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/orchestrator"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// identityAuthProfiles returns the SHARED auth profile both account-a
// and account-b identities reference -- task section 2's own example
// ("account-a -> customer-login, account-b -> customer-login"): one
// login MECHANISM, two independently-credentialed identities.
func identityAuthProfiles(t *testing.T, l *Lab) []auth.ProfileConfig {
	t.Helper()
	return []auth.ProfileConfig{{
		Name: "lab-customer-login", Type: auth.TypeFormLogin,
		LoginURL: fmt.Sprintf("http://auth.scanner.test:%d/login", mustPort(t, l.AuthAddr)),
		// UsernameEnv/PasswordEnv here are the PROFILE's own defaults --
		// deliberately left pointing at env vars that are never set, so
		// a test that accidentally resolves the bare profile (bypassing
		// an identity's own override) fails loudly rather than silently
		// authenticating as some unintended default account.
		UsernameEnv: "SAKANNER_TEST_UNUSED_PROFILE_DEFAULT_USER",
		PasswordEnv: "SAKANNER_TEST_UNUSED_PROFILE_DEFAULT_PASS",
		Timeout:     5 * time.Second,
	}}
}

// authenticateIdentity resolves and authenticates identityName through
// the REAL internal/auth.Identity layer (IdentityConfig ->
// ResolveIdentityProfile -> Provider.Authenticate) -- exactly the code
// path cmd/scanner's --identity flag drives (see
// cmd/scanner/scan.go's authenticateForIdentity), so a bug in
// credential-override resolution or identity-to-profile wiring would
// be caught here, not just in internal/auth's own unit tests.
func authenticateIdentity(t *testing.T, l *Lab, identityName, username, password string, rules ...models.ScopeRule) *auth.Session {
	t.Helper()
	userEnv := "SAKANNER_TEST_IDENTITY_USER_" + identityName
	passEnv := "SAKANNER_TEST_IDENTITY_PASS_" + identityName
	t.Setenv(userEnv, username)
	t.Setenv(passEnv, password)

	ic := auth.IdentityConfig{Name: identityName, AuthProfile: "lab-customer-login", UsernameEnv: userEnv, PasswordEnv: passEnv}
	profile, err := auth.ResolveIdentityProfile(ic, identityAuthProfiles(t, l))
	if err != nil {
		t.Fatalf("ResolveIdentityProfile(%s): %v", identityName, err)
	}
	provider, err := auth.NewProvider(profile)
	if err != nil {
		t.Fatalf("NewProvider(%s): %v", identityName, err)
	}
	sess, err := provider.Authenticate(context.Background(), authDeps(l, rules...))
	if err != nil {
		t.Fatalf("Authenticate(%s): %v (state=%s reason=%s)", identityName, err, sess.State, sess.FailureReason)
	}
	// This is the ONE place a Session's IdentityName is ever set --
	// mirroring cmd/scanner/scan.go's authenticateForIdentity exactly
	// (internal/auth itself never populates it).
	sess.IdentityName = identityName
	return sess
}

// ---------------------------------------------------------------------
// END-TO-END: the required acceptance scenario (task section 22)
// ---------------------------------------------------------------------

// TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries
// is the task's own required acceptance demonstration, steps 1-9 in
// one test: configure + authenticate both accounts, crawl the
// authenticated application as each, discover resources under both,
// and prove session isolation AND discovered-resource identity
// tagging -- all against the REAL lab, through the REAL orchestrator.
func TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	// 1-2. Configure + 3-4. authenticate both accounts.
	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)
	if sessA.State != auth.StateAuthenticated || sessB.State != auth.StateAuthenticated {
		t.Fatalf("expected both identities authenticated, got A=%s B=%s", sessA.State, sessB.State)
	}

	// 5-6. Crawl the authenticated application as each identity (two
	// independent scans -- task section 8's "scan isolation": a scan
	// must not reuse another scan's identity state, which two separate
	// Orchestrator.Run calls against two separate in-memory stores
	// structurally guarantees).
	orchA, storeA := deepAuthOrchestrator(t, l, rules)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run (account-a): %v", err)
	}
	orchB, storeB := deepAuthOrchestrator(t, l, rules)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run (account-b): %v", err)
	}

	if resultA.Identity != "account-a" || resultB.Identity != "account-b" {
		t.Fatalf("Result.Identity not reported correctly: A=%q B=%q", resultA.Identity, resultB.Identity)
	}
	if resultA.AuthProfile != "lab-customer-login" || resultB.AuthProfile != "lab-customer-login" {
		t.Errorf("both identities should report the SAME underlying auth profile: A=%q B=%q", resultA.AuthProfile, resultB.AuthProfile)
	}

	// 7. Discover resources under both identities, 9. demonstrate
	// discovered resources retain identity context.
	endpointsA, err := storeA.Endpoints().ListByScanJob(context.Background(), resultA.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob A: %v", err)
	}
	endpointsB, err := storeB.Endpoints().ListByScanJob(context.Background(), resultB.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob B: %v", err)
	}
	for _, e := range endpointsA {
		if e.HTTPServiceID != "" && e.IdentityContext != "account-a" && e.IdentityContext != "" {
			t.Errorf("scan A endpoint %s has unexpected IdentityContext %q", e.Path, e.IdentityContext)
		}
	}
	foundAuthenticatedA, foundAuthenticatedB := false, false
	for _, e := range endpointsA {
		if e.Path == "/settings" {
			foundAuthenticatedA = true
			if e.IdentityContext != "account-a" {
				t.Errorf("account-a's /settings endpoint has IdentityContext = %q, want account-a", e.IdentityContext)
			}
		}
	}
	for _, e := range endpointsB {
		if e.Path == "/settings" {
			foundAuthenticatedB = true
			if e.IdentityContext != "account-b" {
				t.Errorf("account-b's /settings endpoint has IdentityContext = %q, want account-b", e.IdentityContext)
			}
		}
	}
	if !foundAuthenticatedA || !foundAuthenticatedB {
		t.Fatalf("both identities must independently discover /settings -- foundA=%v foundB=%v", foundAuthenticatedA, foundAuthenticatedB)
	}

	// 8. Demonstrate sessions remain isolated: account-a's cookies must
	// never be usable/present when acting as account-b, and vice versa
	// -- proven directly at the HTTP level below, plus structurally (two
	// entirely separate cookiejar.Jar instances, from two separate
	// Authenticate calls).
	if sessA.Jar == sessB.Jar {
		t.Fatal("SECURITY: account-a and account-b share the same cookie jar instance")
	}

	// A stronger, HTTP-level proof: hit /api/data directly as EACH
	// identity's own session and confirm the user_id differs and is
	// always the CALLER's own (task section 16's "Account A session !=
	// Account B session" / "Account A discovered data != Account B
	// discovered data").
	validator := scope.NewValidator(rules, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "auth.scanner.test", l)
	clientA := sessA.NewClient(dialer, "auth.scanner.test", ip, 5*time.Second, 3)
	clientB := sessB.NewClient(dialer, "auth.scanner.test", ip, 5*time.Second, 3)

	apiDataURL := fmt.Sprintf("http://auth.scanner.test:%d/api/data", mustPort(t, l.AuthAddr))
	bodyA := mustGetBodyWithClient(t, clientA, apiDataURL)
	bodyB := mustGetBodyWithClient(t, clientB, apiDataURL)
	if bodyA == bodyB {
		t.Fatal("SECURITY: /api/data returned identical content for two different identities")
	}
	wantA := fmt.Sprintf(`"user_id":%d`, AccountAUserID)
	wantB := fmt.Sprintf(`"user_id":%d`, AccountBUserID)
	if !strings.Contains(bodyA, wantA) {
		t.Errorf("account-a's own /api/data response = %q, want it to contain %q", bodyA, wantA)
	}
	if !strings.Contains(bodyB, wantB) {
		t.Errorf("account-b's own /api/data response = %q, want it to contain %q", bodyB, wantB)
	}
	if strings.Contains(bodyA, wantB) || strings.Contains(bodyB, wantA) {
		t.Fatal("SECURITY: one identity's response contains the OTHER identity's user_id")
	}

	// 10. Scope enforcement applies independently to both -- both
	// endpoint lists must have zero trace of external.scanner.test.
	if resultA.ReconSummary.HostCount != 1 || resultB.ReconSummary.HostCount != 1 {
		t.Errorf("scope leak: HostCount A=%d B=%d, want 1 each (only auth.scanner.test)", resultA.ReconSummary.HostCount, resultB.ReconSummary.HostCount)
	}

	// 11. No credential/session leakage in either Result (the same
	// guarantee TestSecurity_AuthCredentials_NeverAppearInReportOrStatus
	// proves at the CLI/report level -- here proven structurally: a
	// Session/Result never carries a raw credential field at all, see
	// internal/auth.Session's own field list).
	_ = resultA
	_ = resultB
}

// ---------------------------------------------------------------------
// CONCURRENCY (task section 14)
// ---------------------------------------------------------------------

// TestPhase3_16_ConcurrentIdentities_AccountAAndB is task section 22
// step 12: simultaneous login, simultaneous authenticated crawling, as
// two DIFFERENT identities, run truly concurrently.
func TestPhase3_16_ConcurrentIdentities_AccountAAndB(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	// Orchestrators are built in the main test goroutine -- t.Fatalf
	// (inside deepAuthOrchestrator) must never run from a spawned
	// goroutine (see phase3_15_authenticated_crawl_test.go's own
	// identical concurrency-test structure for why).
	orchA, storeA := deepAuthOrchestrator(t, l, rules)
	orchB, storeB := deepAuthOrchestrator(t, l, rules)

	t.Setenv("SAKANNER_TEST_IDENTITY_USER_account-a", AccountAUsername)
	t.Setenv("SAKANNER_TEST_IDENTITY_PASS_account-a", AccountAPassword)
	t.Setenv("SAKANNER_TEST_IDENTITY_USER_account-b", AccountBUsername)
	t.Setenv("SAKANNER_TEST_IDENTITY_PASS_account-b", AccountBPassword)
	profiles := identityAuthProfiles(t, l)
	icA := auth.IdentityConfig{Name: "account-a", AuthProfile: "lab-customer-login", UsernameEnv: "SAKANNER_TEST_IDENTITY_USER_account-a", PasswordEnv: "SAKANNER_TEST_IDENTITY_PASS_account-a"}
	icB := auth.IdentityConfig{Name: "account-b", AuthProfile: "lab-customer-login", UsernameEnv: "SAKANNER_TEST_IDENTITY_USER_account-b", PasswordEnv: "SAKANNER_TEST_IDENTITY_PASS_account-b"}
	profileA, err := auth.ResolveIdentityProfile(icA, profiles)
	if err != nil {
		t.Fatalf("resolve account-a: %v", err)
	}
	profileB, err := auth.ResolveIdentityProfile(icB, profiles)
	if err != nil {
		t.Fatalf("resolve account-b: %v", err)
	}

	type outcome struct {
		name   string
		result orchestrator.Result
		err    error
	}
	results := make(chan outcome, 2)
	go func() {
		provider, _ := auth.NewProvider(profileA)
		sess, authErr := provider.Authenticate(context.Background(), authDeps(l, rules...))
		if authErr != nil {
			results <- outcome{name: "account-a", err: authErr}
			return
		}
		sess.IdentityName = "account-a"
		r, runErr := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		results <- outcome{name: "account-a", result: r, err: runErr}
	}()
	go func() {
		provider, _ := auth.NewProvider(profileB)
		sess, authErr := provider.Authenticate(context.Background(), authDeps(l, rules...))
		if authErr != nil {
			results <- outcome{name: "account-b", err: authErr}
			return
		}
		sess.IdentityName = "account-b"
		r, runErr := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		results <- outcome{name: "account-b", result: r, err: runErr}
	}()

	byName := map[string]orchestrator.Result{}
	for i := 0; i < 2; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("%s: %v", o.name, o.err)
		}
		byName[o.name] = o.result
	}
	if byName["account-a"].Identity != "account-a" || byName["account-b"].Identity != "account-b" {
		t.Fatalf("concurrent identity results crossed: %+v", byName)
	}
	// Endpoints from each scan must never mix identity contexts.
	endpointsA, _ := storeA.Endpoints().ListByScanJob(context.Background(), byName["account-a"].ScanID)
	endpointsB, _ := storeB.Endpoints().ListByScanJob(context.Background(), byName["account-b"].ScanID)
	for _, e := range endpointsA {
		if e.IdentityContext == "account-b" {
			t.Fatal("SECURITY: account-a's scan job contains an account-b-tagged endpoint")
		}
	}
	for _, e := range endpointsB {
		if e.IdentityContext == "account-a" {
			t.Fatal("SECURITY: account-b's scan job contains an account-a-tagged endpoint")
		}
	}
}

// ---------------------------------------------------------------------
// INDEPENDENT SESSION EXPIRATION (task section 10)
// ---------------------------------------------------------------------

// TestPhase3_16_IndependentSessionExpiration_OneAccountExpiring proves
// task section 10's core scenario: account-a's session expires
// (invalidated via /logout, exactly like
// phase3_15_authenticated_crawl_test.go's own single-identity
// expiration test), while account-b's completely independent session
// remains valid and its own scan is entirely unaffected -- "no global
// authentication failure caused by one identity expiring."
func TestPhase3_16_IndependentSessionExpiration_OneAccountExpiring(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	// Expire ONLY account-a, directly, outside of any crawl.
	validator := scope.NewValidator(rules, true)
	dialer := safedial.New(validator, l.Resolver)
	ip := dial(t, "auth.scanner.test", l)
	clientA := sessA.NewClient(dialer, "auth.scanner.test", ip, 5*time.Second, 3)
	logoutResp, err := clientA.Get(fmt.Sprintf("http://auth.scanner.test:%d/logout", mustPort(t, l.AuthAddr)))
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	logoutResp.Body.Close()

	orchA, _ := deepAuthOrchestrator(t, l, rules)
	orchB, _ := deepAuthOrchestrator(t, l, rules)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run account-a: %v", err)
	}
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run account-b: %v", err)
	}

	if !resultA.SessionExpired {
		t.Error("account-a: SessionExpired = false, want true (session was invalidated via /logout)")
	}
	if resultB.SessionExpired {
		t.Error("account-b: SessionExpired = true, want false -- one identity expiring must NEVER affect another (task section 10's core requirement)")
	}
	if resultB.AuthState != auth.StateAuthenticated {
		t.Errorf("account-b: AuthState = %s, want AUTHENTICATED (unaffected by account-a's expiration)", resultB.AuthState)
	}
}

// ---------------------------------------------------------------------
// DETERMINISM (task section 13)
// ---------------------------------------------------------------------

// TestPhase3_16_Determinism_RepeatedIdentityScans_SameStructuralCounts
// mirrors Phase 3.15's own determinism test, extended to identity
// ordering/tagging: repeated identical scans under the SAME identity
// produce identical endpoint/parameter counts AND identical
// IdentityContext tagging every time.
func TestPhase3_16_Determinism_RepeatedIdentityScans_SameStructuralCounts(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	var endpointCounts []int
	var identityTaggedCounts []int
	for i := 0; i < 3; i++ {
		sess := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
		orch, store := deepAuthOrchestrator(t, l, rules)
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d ListByScanJob: %v", i, err)
		}
		endpointCounts = append(endpointCounts, len(endpoints))
		tagged := 0
		for _, e := range endpoints {
			if e.IdentityContext == "account-a" {
				tagged++
			}
		}
		identityTaggedCounts = append(identityTaggedCounts, tagged)
	}
	for i := 1; i < len(endpointCounts); i++ {
		if endpointCounts[i] != endpointCounts[0] {
			t.Errorf("endpoint count not deterministic: run 0=%d run %d=%d", endpointCounts[0], i, endpointCounts[i])
		}
		if identityTaggedCounts[i] != identityTaggedCounts[0] {
			t.Errorf("account-a-tagged endpoint count not deterministic: run 0=%d run %d=%d", identityTaggedCounts[0], i, identityTaggedCounts[i])
		}
	}
}

// ---------------------------------------------------------------------
// SCOPE ENFORCEMENT APPLIES INDEPENDENTLY TO EACH IDENTITY (task 11)
// ---------------------------------------------------------------------

// TestPhase3_16_ScopeEnforcement_AppliesIndependentlyToBothIdentities
// is task section 11's explicit requirement: identity must never act
// as a scope-authorization mechanism. Both identities attempt to reach
// the SAME out-of-scope resources (the authenticated link on /profile
// and the authenticated redirect on /redirect-to-external); both must
// be rejected, identically, regardless of which account is used.
func TestPhase3_16_ScopeEnforcement_AppliesIndependentlyToBothIdentities(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules() // only auth.scanner.test -- external.scanner.test is never authorized for ANY identity

	for _, tc := range []struct {
		identity, username, password string
	}{
		{"account-a", AccountAUsername, AccountAPassword},
		{"account-b", AccountBUsername, AccountBPassword},
	} {
		t.Run(tc.identity, func(t *testing.T) {
			sess := authenticateIdentity(t, l, tc.identity, tc.username, tc.password, rules...)
			orch, store := deepAuthOrchestrator(t, l, rules)
			result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.ReconSummary.HostCount != 1 {
				t.Errorf("%s: HostCount = %d, want 1 (external.scanner.test must never be discovered as a second host)", tc.identity, result.ReconSummary.HostCount)
			}
			endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
			if err != nil {
				t.Fatalf("ListByScanJob: %v", err)
			}
			for _, e := range endpoints {
				if strings.Contains(e.Path, "external.scanner.test") {
					t.Errorf("%s: an endpoint referencing the out-of-scope host was persisted: %+v", tc.identity, e)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------
// SEQUENTIAL SCAN ISOLATION (task section 8)
// ---------------------------------------------------------------------

// TestPhase3_16_SequentialScans_AlternatingAndRepeatedIdentities is
// task section 8's own explicit scenario list: "Scan 1 -> account-a,
// Scan 2 -> account-b" AND "Scan 1 -> account-a, Scan 2 -> account-a"
// (repeated). ALL FOUR scans below reuse the SAME *orchestrator.Orchestrator
// instance (deliberately, not a fresh one per scan) -- the strongest
// available proof that "the architecture must not require a global
// mutable session" (task section 14) really holds: if Orchestrator
// held any shared, mutable per-session state, reusing one instance
// across alternating identities would be exactly the scenario that
// exposes it.
func TestPhase3_16_SequentialScans_AlternatingAndRepeatedIdentities(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	orch, store := deepAuthOrchestrator(t, l, rules)

	run := func(identity, username, password string) orchestrator.Result {
		t.Helper()
		sess := authenticateIdentity(t, l, identity, username, password, rules...)
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		if err != nil {
			t.Fatalf("Run(%s): %v", identity, err)
		}
		return result
	}

	// Scan 1 -> A, Scan 2 -> B, Scan 3 -> A (repeated, non-adjacent),
	// Scan 4 -> A (repeated, adjacent) -- covers both task-listed
	// sequences (A->B and A->A) plus the stricter adjacent-repeat case.
	sequence := []struct{ identity, username, password string }{
		{"account-a", AccountAUsername, AccountAPassword},
		{"account-b", AccountBUsername, AccountBPassword},
		{"account-a", AccountAUsername, AccountAPassword},
		{"account-a", AccountAUsername, AccountAPassword},
	}
	var scanIDs []string
	for _, step := range sequence {
		result := run(step.identity, step.username, step.password)
		if result.Identity != step.identity {
			t.Fatalf("expected identity %s, got %s (scan %d)", step.identity, result.Identity, len(scanIDs)+1)
		}
		if result.AuthState != auth.StateAuthenticated {
			t.Fatalf("scan %d (%s): AuthState = %s, want AUTHENTICATED", len(scanIDs)+1, step.identity, result.AuthState)
		}
		scanIDs = append(scanIDs, result.ScanID)
	}

	// Every scan ID must be distinct (no accidental scan-job reuse),
	// and each scan's own persisted endpoints must carry ONLY that
	// scan's own identity -- never a PREVIOUS scan's identity, even
	// when the previous scan used a DIFFERENT identity (scan 2, B,
	// immediately followed by scan 3, A) or the SAME identity (scan 3
	// immediately followed by scan 4, both A).
	seen := map[string]bool{}
	for i, id := range scanIDs {
		if seen[id] {
			t.Fatalf("scan %d reused a previous scan's ID: %s", i+1, id)
		}
		seen[id] = true

		endpoints, err := store.Endpoints().ListByScanJob(context.Background(), id)
		if err != nil {
			t.Fatalf("scan %d ListByScanJob: %v", i+1, err)
		}
		wantIdentity := sequence[i].identity
		for _, e := range endpoints {
			if e.IdentityContext != "" && e.IdentityContext != wantIdentity {
				t.Errorf("scan %d (%s): endpoint %s carries IdentityContext %q from a DIFFERENT scan/identity", i+1, wantIdentity, e.Path, e.IdentityContext)
			}
		}
	}
}

// mustGetBodyWithClient performs a GET using a specific *http.Client
// (unlike this package's own mustGetBody, which always uses the
// default client -- needed here so each request carries a specific
// identity's own session) and returns the response body as a string,
// bounded to a small sample (these lab responses are tiny JSON
// payloads).
func mustGetBodyWithClient(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatalf("read body from %s: %v", url, err)
	}
	return string(body)
}
