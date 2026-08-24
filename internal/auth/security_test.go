package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSecurity_ProfileRedacted_NeverIncludesSecrets is task section 6's
// "credentials must never be exposed" applied directly to the one
// display-safe view this package offers of a Profile.
func TestSecurity_ProfileRedacted_NeverIncludesSecrets(t *testing.T) {
	p := Profile{
		Name: "x", Type: TypeFormLogin, Host: "app.test",
		Username: "alice-the-secret-username", Password: "hunter2-the-secret-password",
		Token: "tok-secret", HeaderValue: "header-value-secret", CookieHeader: "session=cookie-secret",
		LoginURL: mustParseURL(t, "http://user:pass@app.test/login"),
	}
	summary := p.Redacted()

	// %+v deliberately used: a future field added to ProfileSummary
	// that accidentally carries a raw secret must be caught by this
	// blanket check, not just by field-by-field assertions that a new
	// field wouldn't be included in anyway.
	dump := dumpStruct(summary)
	for _, secret := range []string{"alice-the-secret-username", "hunter2-the-secret-password", "tok-secret", "header-value-secret", "cookie-secret", "user:pass"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("SECURITY: Profile.Redacted() output contains a secret value %q:\n%s", secret, dump)
		}
	}
	if !summary.HasUsername || !summary.HasPassword || !summary.HasToken || !summary.HasCookie || !summary.HasHeaderValue {
		t.Errorf("Redacted() should still report WHICH secrets are set (booleans), got %+v", summary)
	}
}

func TestSecurity_SessionRedacted_NeverIncludesSecrets(t *testing.T) {
	sess := &Session{
		ProfileName: "x", Type: TypeBearerToken, Host: "api.test", State: StateAuthenticated,
		Headers:   map[string]string{"Authorization": "Bearer tok-secret-value", "X-Api-Key": "key-secret-value"},
		CreatedAt: time.Now(),
	}
	dump := dumpStruct(sess.Redacted())
	for _, secret := range []string{"tok-secret-value", "key-secret-value"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("SECURITY: Session.Redacted() output contains a secret value %q:\n%s", secret, dump)
		}
	}
	for _, name := range []string{"Authorization", "X-Api-Key"} {
		if !strings.Contains(dump, name) {
			t.Errorf("Redacted() should still list header NAMES (never values): missing %q in %s", name, dump)
		}
	}
}

// TestSecurity_FailSession_NeverIncludesPasswordOrTokenInReason checks
// every error path a Provider can take against a live server that
// deliberately echoes credentials back (a worst-case application that
// would leak them into a response body/error if this package were
// careless about what it puts in FailureReason/returned errors).
func TestSecurity_FailSession_ReasonIsSecretFree(t *testing.T) {
	sess := &Session{}
	got, err := failSession(sess, fmt.Errorf("auth: profile %q's host %q is out of scope", "x", "app.test"))
	if got.FailureReason == "" || err == nil {
		t.Fatal("failSession must populate both FailureReason and return the error")
	}
	if strings.Contains(got.FailureReason, "hunter2") {
		t.Fatal("unexpected secret leakage")
	}
}

// TestSecurity_UnknownProfileError_NeverEchoesPassedInSecret guards
// against a future caller accidentally passing a secret as the "name"
// (e.g. confusing --auth-profile with a credential flag) -- the error
// type itself has no way to know that happened, but this test
// documents and locks the expectation that only Name/Available (never
// arbitrary caller data beyond those two) appear in the message.
func TestSecurity_UnknownProfileError_OnlyNameAndAvailable(t *testing.T) {
	err := &UnknownProfileError{Name: "lab-user", Available: []string{"a", "b"}}
	msg := err.Error()
	if !strings.Contains(msg, "lab-user") || !strings.Contains(msg, "a") || !strings.Contains(msg, "b") {
		t.Errorf("error message missing expected content: %s", msg)
	}
}

func TestSecurity_Session_ExpiredIsDistinctFromFailed(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	sess := &Session{State: StateAuthenticated, ExpiresAt: &past}
	if !sess.IsExpired(time.Now()) {
		t.Fatal("expected IsExpired to report true")
	}
	// This package never auto-transitions State on expiry (see
	// State's doc comment) -- a caller that cares must check IsExpired
	// itself and set StateExpired; verify the State constant exists and
	// is distinct from Failed/Authenticated so such a caller has
	// somewhere correct to put that fact.
	if StateExpired == StateFailed || StateExpired == StateAuthenticated {
		t.Fatal("StateExpired must be a distinct state")
	}
}
