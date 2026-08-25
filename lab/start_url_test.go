// General web application start-URL/base-path support: real
// orchestrator + real lab integration tests using harness_auth.go's
// /subpath-app/* fixture (an application hosted under a subpath that
// "/" has no link into at all, whose own login handler additionally
// gates on its own named submit button being present in the POST
// body -- see harness_auth.go's doc comment on that fixture). These
// tests are deliberately NOT DVWA-specific: /subpath-app/ stands in
// for "any application mounted under a base path," proving the
// general mechanism (internal/orchestration.Pipeline.CrawlStartPath)
// rather than anything tied to a particular real-world app.
package lab

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/orchestrator"
	"sakanner/pkg/models"
)

// authenticateSubpathAccount mirrors phase3_14_auth_test.go's own
// authenticateAccount, but points LoginURL at /subpath-app/login
// instead of the root /login fixture -- proving the same
// FormLoginProvider flow works against a login form mounted under a
// subpath, and (since /subpath-app/login's own handler rejects any
// submission missing its "do_login" submit-button field) that
// internal/auth/htmlform.go's inclusion of type="submit" fields is
// actually load-bearing: reverting that fix would make this
// authentication attempt fail with "login response status 400."
func authenticateSubpathAccount(t *testing.T, l *Lab, username, password string, rules ...models.ScopeRule) *auth.Session {
	t.Helper()
	t.Setenv("SAKANNER_LAB_SUBPATH_USER_"+username, username)
	t.Setenv("SAKANNER_LAB_SUBPATH_PASS_"+username, password)
	profile, err := auth.ResolveProfile(auth.ProfileConfig{
		Name: "lab-subpath-" + username, Type: auth.TypeFormLogin,
		LoginURL:    fmt.Sprintf("http://auth.scanner.test:%d/subpath-app/login", mustPort(t, l.AuthAddr)),
		UsernameEnv: "SAKANNER_LAB_SUBPATH_USER_" + username, PasswordEnv: "SAKANNER_LAB_SUBPATH_PASS_" + username,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	provider, err := auth.NewProvider(profile)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	sess, err := provider.Authenticate(context.Background(), authDeps(l, rules...))
	if err != nil {
		t.Fatalf("Authenticate: %v (state=%s reason=%s)", err, sess.State, sess.FailureReason)
	}
	return sess
}

// TestStartURL_LoginSucceedsWithSubmitButtonField proves, at the
// internal/auth level (no crawling involved), that a login form whose
// processing is gated on its own submit button's name being present
// in the POST body (the fixture returns 400 "missing submit field"
// otherwise, mirroring a common server-side idiom such as PHP's
// isset($_POST['do_login'])) now authenticates successfully. Before
// internal/auth/htmlform.go's fix, extractLoginForm excluded
// type="submit" fields entirely, so this exact scenario would fail
// with "authentication failed: login response status 400".
func TestStartURL_LoginSucceedsWithSubmitButtonField(t *testing.T) {
	l := testAuthLab(t)
	rules := []models.ScopeRule{{Value: "auth.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}

	sess := authenticateSubpathAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	if sess.State != auth.StateAuthenticated {
		t.Fatalf("authentication did not succeed: state=%s reason=%s", sess.State, sess.FailureReason)
	}
}

// TestStartURL_AuthenticatedCrawlReachesSubpathApp is the vertical
// slice for the start-URL/base-path feature: with
// Pipeline.CrawlStartPath pointed at /subpath-app/ (the equivalent of
// an operator passing --start-url /subpath-app/ on the CLI), an
// authenticated crawl starting there discovers /subpath-app/dashboard
// and, following its own in-page link, /subpath-app/profile -- pages
// with no link into them from "/" at all, so their discovery is
// direct proof that CrawlStartPath actually redirected the crawl's
// own starting point, not merely that authentication succeeded.
func TestStartURL_AuthenticatedCrawlReachesSubpathApp(t *testing.T) {
	l := testAuthLab(t)
	rules := []models.ScopeRule{{Value: "auth.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}

	sess := authenticateSubpathAccount(t, l, AccountAUsername, AccountAPassword, rules...)
	if sess.State != auth.StateAuthenticated {
		t.Fatalf("authentication did not succeed: state=%s reason=%s", sess.State, sess.FailureReason)
	}

	orch, store := authOrchestrator(t, l, rules)
	orch.Pipeline.CrawlStartPath = "/subpath-app/"

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.AuthState != auth.StateAuthenticated || result.AuthProfile != sess.ProfileName {
		t.Errorf("result auth fields = state=%s profile=%s, want AUTHENTICATED / %s", result.AuthState, result.AuthProfile, sess.ProfileName)
	}

	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	if !paths["/subpath-app/dashboard"] {
		t.Errorf("authenticated crawl starting at /subpath-app/ did not discover /subpath-app/dashboard -- endpoints found: %v", paths)
	}
	if !paths["/subpath-app/profile"] {
		t.Errorf("authenticated crawl starting at /subpath-app/ did not discover /subpath-app/profile -- endpoints found: %v", paths)
	}
}

// TestStartURL_DefaultRootCrawl_NeverReachesSubpathApp is the negative
// control: with CrawlStartPath left at its default ("/"), nothing
// under /subpath-app/ is ever discovered, since -- exactly like a
// real application mounted under a base path such as /DVWA/ -- "/"
// has no link into it at all. Proves CrawlStartPath is load-bearing in
// the other test above, not a no-op that would have reached
// /subpath-app/ either way.
func TestStartURL_DefaultRootCrawl_NeverReachesSubpathApp(t *testing.T) {
	l := testAuthLab(t)
	rules := []models.ScopeRule{{Value: "auth.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := authOrchestrator(t, l, rules)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, e := range endpoints {
		if strings.HasPrefix(e.Path, "/subpath-app/") {
			t.Errorf("default root crawl (CrawlStartPath unset) discovered %q -- /subpath-app/ should be unreachable from \"/\"", e.Path)
		}
	}
}
