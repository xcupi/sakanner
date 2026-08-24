package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// Phase 3.16 task section 19's adversarial suite, covering the
// identity-specific scenarios not already exercised by Phase 3.14/
// 3.15's own adversarial tests (formlogin_test.go, security_test.go,
// adversarial_test.go) or by lab/phase3_16_multi_identity_test.go's
// full-stack versions of the same concerns.

// TestAdversarial_SharedAuthProfile_NoCredentialContamination is the
// one adversarial scenario genuinely specific to Phase 3.16's own
// design (task section 19's "shared auth profile contamination"): two
// identities referencing the SAME auth profile, resolved and
// authenticated in immediate succession, must never leak one's
// credentials into the other's resolved Profile or Session.
func TestAdversarial_SharedAuthProfile_NoCredentialContamination(t *testing.T) {
	t.Setenv("SHARED_DEFAULT_USER", "should-never-be-used")
	t.Setenv("SHARED_DEFAULT_PASS", "should-never-be-used-either")
	t.Setenv("USER_A", "alice")
	t.Setenv("PASS_A", "alice-secret")
	t.Setenv("USER_B", "bob")
	t.Setenv("PASS_B", "bob-secret")

	profiles := []ProfileConfig{{
		Name: "shared-login", Type: TypeFormLogin, LoginURL: "http://shared.test/login",
		UsernameEnv: "SHARED_DEFAULT_USER", PasswordEnv: "SHARED_DEFAULT_PASS",
	}}
	icA := IdentityConfig{Name: "account-a", AuthProfile: "shared-login", UsernameEnv: "USER_A", PasswordEnv: "PASS_A"}
	icB := IdentityConfig{Name: "account-b", AuthProfile: "shared-login", UsernameEnv: "USER_B", PasswordEnv: "PASS_B"}

	// Resolve BOTH from the exact same underlying []ProfileConfig slice,
	// interleaved, to catch any accidental shared mutable state in
	// ResolveIdentityProfile/ResolveProfile (e.g. a profile config
	// struct mutated in place rather than copied).
	profileA1, err := ResolveIdentityProfile(icA, profiles)
	if err != nil {
		t.Fatalf("resolve A (1st): %v", err)
	}
	profileB, err := ResolveIdentityProfile(icB, profiles)
	if err != nil {
		t.Fatalf("resolve B: %v", err)
	}
	profileA2, err := ResolveIdentityProfile(icA, profiles)
	if err != nil {
		t.Fatalf("resolve A (2nd): %v", err)
	}

	if profileA1.Username != "alice" || profileA2.Username != "alice" {
		t.Fatalf("account-a's own credential resolution is unstable: 1st=%q 2nd=%q", profileA1.Username, profileA2.Username)
	}
	if profileB.Username != "bob" {
		t.Fatalf("account-b resolved to %q, want bob", profileB.Username)
	}
	if profileA1.Username == profileB.Username || profileA1.Password == profileB.Password {
		t.Fatal("SECURITY: account-a and account-b resolved to the same credentials despite independent overrides")
	}
	// The underlying profiles slice itself must be untouched --
	// ResolveIdentityProfile must never mutate the caller's own slice.
	if profiles[0].UsernameEnv != "SHARED_DEFAULT_USER" {
		t.Fatalf("SECURITY: the shared ProfileConfig was mutated in place: %+v", profiles[0])
	}
}

// TestAdversarial_IdentityNameInjection_ShapedStrings proves identity
// names containing shell/SQL/path-traversal/control-character-shaped
// content are handled safely -- accepted as opaque labels (this
// package performs no shell execution, no raw SQL string
// concatenation, and no filesystem access keyed on an identity name at
// all, so there is no injection SURFACE to begin with), never causing
// a crash, and never silently truncated/mangled in a way that could
// cause TWO DIFFERENT malicious names to collide.
func TestAdversarial_IdentityNameInjection_ShapedStrings(t *testing.T) {
	shapedNames := []string{
		"account-a; rm -rf /",
		"account' OR '1'='1",
		"../../../etc/passwd",
		"account\x00a",
		"account\na-newline",
		strings.Repeat("a", 10000),
	}
	for _, name := range shapedNames {
		t.Run("", func(t *testing.T) {
			ic := IdentityConfig{Name: name, AuthProfile: "p"}
			id := NewIdentity(ic)
			if id.Name != name {
				t.Errorf("identity name was altered: got %q", id.Name)
			}
			// Must not panic when building a registry, resolving, or
			// redacting.
			reg, err := NewIdentityRegistry([]IdentityConfig{ic})
			if err != nil {
				t.Fatalf("NewIdentityRegistry: %v", err)
			}
			if _, ok := reg.Get(name); !ok {
				t.Error("registry lookup failed for the exact same shaped name")
			}
			_ = id.Redacted() // must not panic
		})
	}
}

// TestAdversarial_IdentityNameInjection_TwoDistinctShapedNames_NeverCollide
// ensures two DIFFERENT adversarially-shaped names are never conflated
// into the same registry entry (e.g. via truncation at a null byte).
func TestAdversarial_IdentityNameInjection_TwoDistinctShapedNames_NeverCollide(t *testing.T) {
	nameA := "account\x00a"
	nameB := "account\x00b"
	reg, err := NewIdentityRegistry([]IdentityConfig{
		{Name: nameA, AuthProfile: "p"},
		{Name: nameB, AuthProfile: "p"},
	})
	if err != nil {
		t.Fatalf("NewIdentityRegistry: %v", err)
	}
	if len(reg.List()) != 2 {
		t.Fatalf("got %d identities, want 2 (names must not collide)", len(reg.List()))
	}
}

// TestAdversarial_MalformedIdentityProfileReference_Injection proves an
// identity's AuthProfile field containing injection-shaped content
// simply fails to resolve (no matching profile), rather than matching
// something unintended.
func TestAdversarial_MalformedIdentityProfileReference_Injection(t *testing.T) {
	profiles := []ProfileConfig{{Name: "customer-login", Type: TypeBearerToken, TokenEnv: "T", ScopeHost: "h"}}
	for _, badRef := range []string{"customer-login' OR '1'='1", "customer-login\x00", "", "CUSTOMER-LOGIN"} {
		t.Run(badRef, func(t *testing.T) {
			ic := IdentityConfig{Name: "x", AuthProfile: badRef}
			_, err := ResolveIdentityProfile(ic, profiles)
			if err == nil {
				t.Errorf("expected ResolveIdentityProfile to reject auth_profile %q, got no error", badRef)
			}
		})
	}
}

// TestAdversarial_SessionFixation_IdentityCannotBeReassignedPostHoc
// documents and locks that a Session's IdentityName, once set by the
// ONE legitimate caller (cmd/scanner's authenticateForIdentity), is a
// plain string field with no protected/enforced immutability at the Go
// level -- but every consumer of Session (internal/orchestration,
// internal/orchestrator) only ever READS it, never writes it, so there
// is no code path within this codebase that could reassign an
// in-flight session's identity mid-scan. This test pins that
// read-only-after-construction usage pattern for CookiesFor/HeadersFor/
// JarFor, which key ONLY on Host, never on IdentityName -- so even if
// IdentityName were (hypothetically) attacker-influenced, it grants no
// additional access, since it is not part of the host-pinning security
// check at all.
func TestAdversarial_SessionFixation_IdentityNameNotPartOfSecurityCheck(t *testing.T) {
	sess := &Session{Host: "app.test", IdentityName: "account-a", Headers: map[string]string{"Authorization": "Bearer tok"}}
	// Changing IdentityName after construction must have NO effect on
	// what CookiesFor/HeadersFor release -- only Host matters.
	sess.IdentityName = "account-b-attacker-supplied"
	if got := sess.HeadersFor("app.test"); got["Authorization"] != "Bearer tok" {
		t.Fatal("HeadersFor stopped working after IdentityName was changed -- IdentityName must never gate access")
	}
	if got := sess.HeadersFor("other.test"); len(got) != 0 {
		t.Fatal("HeadersFor released headers for a different host regardless of IdentityName manipulation")
	}
}

// TestAdversarial_CancellationDuringIdentityAuthentication_NoHang is
// task section 19's "cancellation during login" applied specifically
// to the identity-resolution path (ResolveIdentityProfile +
// Authenticate), not just the bare-profile path Phase 3.15 already
// covers.
func TestAdversarial_CancellationDuringIdentityAuthentication_NoHang(t *testing.T) {
	srv := newIPServer(t, "127.0.0.222", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Write([]byte(loginPageHTML))
	}))
	profiles := []ProfileConfig{{
		Name: "p", Type: TypeFormLogin, LoginURL: fmt.Sprintf("http://cancel-identity.test:%d/login", serverPort(t, srv)),
		UsernameEnv: "UNUSED_PROFILE_USER", PasswordEnv: "UNUSED_PROFILE_PASS", Timeout: 10 * time.Second,
	}}
	t.Setenv("USER_A", "alice")
	t.Setenv("PASS_A", "pw")
	ic := IdentityConfig{Name: "account-a", AuthProfile: "p", UsernameEnv: "USER_A", PasswordEnv: "PASS_A"}
	profile, err := ResolveIdentityProfile(ic, profiles)
	if err != nil {
		t.Fatalf("ResolveIdentityProfile: %v", err)
	}
	prov, _ := NewProvider(profile)

	resolver := dns.NewFakeResolver()
	resolver.Hosts["cancel-identity.test"] = []net.IP{serverIP(t, srv)}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	var sess *Session
	var authErr error
	go func() {
		sess, authErr = prov.Authenticate(ctx, deps(t, resolver, allowAllValidator{}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate did not return within 5s of cancellation during an identity-based login")
	}
	if authErr == nil || sess.State != StateFailed {
		t.Fatalf("expected AUTHENTICATION_FAILED after cancellation, got state=%s err=%v", sess.State, authErr)
	}
}
