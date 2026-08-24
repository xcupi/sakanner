package auth

import (
	"strings"
	"testing"
)

func TestNewIdentity_ConfiguredByDefault(t *testing.T) {
	id := NewIdentity(IdentityConfig{Name: "account-a", AuthProfile: "customer-login"})
	if id.State != IdentityConfigured {
		t.Errorf("State = %s, want IDENTITY_CONFIGURED", id.State)
	}
	if id.Session != nil {
		t.Error("a freshly-configured identity must not have a Session yet")
	}
}

func TestNewIdentity_Disabled(t *testing.T) {
	id := NewIdentity(IdentityConfig{Name: "account-a", AuthProfile: "customer-login", Disabled: true})
	if id.State != IdentityDisabled {
		t.Errorf("State = %s, want IDENTITY_DISABLED", id.State)
	}
}

func TestIdentity_WithSession_MapsStatesCorrectly(t *testing.T) {
	tests := []struct {
		name string
		sess *Session
		err  error
		want IdentityState
	}{
		{"authenticated", &Session{State: StateAuthenticated}, nil, IdentityAuthenticated},
		{"failed", &Session{State: StateFailed, FailureReason: "bad creds"}, errFake, IdentityAuthFailed},
		{"expired", &Session{State: StateExpired}, nil, IdentityExpired},
		{"authenticating", &Session{State: StateAuthenticating}, nil, IdentityAuthenticating},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := NewIdentity(IdentityConfig{Name: "x", AuthProfile: "y"})
			got := id.WithSession(tc.sess, tc.err)
			if got.State != tc.want {
				t.Errorf("State = %s, want %s", got.State, tc.want)
			}
			if got.Session != tc.sess {
				t.Error("WithSession did not attach the given Session")
			}
		})
	}
}

func TestIdentity_WithSession_NilSessionNonNilError(t *testing.T) {
	id := NewIdentity(IdentityConfig{Name: "x", AuthProfile: "y"})
	got := id.WithSession(nil, errFake)
	if got.State != IdentityAuthFailed {
		t.Errorf("State = %s, want IDENTITY_AUTH_FAILED", got.State)
	}
	if got.FailureReason == "" {
		t.Error("FailureReason must be populated from the error when sess is nil")
	}
}

var errFake = &fakeErr{"authentication failed"}

type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }

func TestIdentity_Redacted_NoSecrets(t *testing.T) {
	sess := &Session{
		ProfileName: "customer-login", IdentityName: "account-a", State: StateAuthenticated,
		Headers: map[string]string{"Authorization": "Bearer super-secret-token"},
	}
	id := Identity{Name: "account-a", AuthProfile: "customer-login", State: IdentityAuthenticated, Session: sess}
	summary := id.Redacted()
	dump := dumpStruct(summary)
	if strings.Contains(dump, "super-secret-token") {
		t.Fatalf("SECURITY: Identity.Redacted() leaked a secret: %s", dump)
	}
	if summary.Name != "account-a" || summary.AuthProfile != "customer-login" {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestIdentityRegistry_DeterministicOrder(t *testing.T) {
	configs := []IdentityConfig{
		{Name: "account-c", AuthProfile: "p"},
		{Name: "account-a", AuthProfile: "p"},
		{Name: "account-b", AuthProfile: "p"},
	}
	reg, err := NewIdentityRegistry(configs)
	if err != nil {
		t.Fatalf("NewIdentityRegistry: %v", err)
	}
	got := reg.List()
	want := []string{"account-c", "account-a", "account-b"} // declaration order, NOT sorted
	if len(got) != len(want) {
		t.Fatalf("got %d identities, want %d", len(got), len(want))
	}
	for i, ic := range got {
		if ic.Name != want[i] {
			t.Errorf("List()[%d].Name = %q, want %q (declaration order must be preserved)", i, ic.Name, want[i])
		}
	}
}

func TestIdentityRegistry_DuplicateName_Rejected(t *testing.T) {
	_, err := NewIdentityRegistry([]IdentityConfig{
		{Name: "account-a", AuthProfile: "p1"},
		{Name: "account-a", AuthProfile: "p2"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected a duplicate-name error, got: %v", err)
	}
}

func TestIdentityRegistry_EmptyName_Rejected(t *testing.T) {
	_, err := NewIdentityRegistry([]IdentityConfig{{Name: "", AuthProfile: "p"}})
	if err == nil {
		t.Fatal("expected an error for an empty identity name")
	}
}

func TestIdentityRegistry_Names_Sorted(t *testing.T) {
	reg, err := NewIdentityRegistry([]IdentityConfig{{Name: "zzz", AuthProfile: "p"}, {Name: "aaa", AuthProfile: "p"}})
	if err != nil {
		t.Fatalf("NewIdentityRegistry: %v", err)
	}
	names := reg.Names()
	if len(names) != 2 || names[0] != "aaa" || names[1] != "zzz" {
		t.Errorf("Names() = %v, want sorted [aaa zzz]", names)
	}
}

func TestUnknownIdentityError_Message(t *testing.T) {
	err := &UnknownIdentityError{Name: "account-z", Available: []string{"account-a", "account-b"}}
	msg := err.Error()
	for _, want := range []string{"account-z", "account-a", "account-b"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestResolveIdentityProfile_InheritsProfileMechanism_OverridesCredentials(t *testing.T) {
	t.Setenv("SHARED_USER", "shared-default-user")
	t.Setenv("SHARED_PASS", "shared-default-pass")
	t.Setenv("ACCOUNT_A_USER", "alice")
	t.Setenv("ACCOUNT_A_PASS", "alice-password")

	profiles := []ProfileConfig{{
		Name: "customer-login", Type: TypeFormLogin,
		LoginURL: "http://app.test/login", UsernameEnv: "SHARED_USER", PasswordEnv: "SHARED_PASS",
		UsernameField: "email", SuccessTextContains: "Welcome",
	}}
	ic := IdentityConfig{Name: "account-a", AuthProfile: "customer-login", UsernameEnv: "ACCOUNT_A_USER", PasswordEnv: "ACCOUNT_A_PASS"}

	profile, err := ResolveIdentityProfile(ic, profiles)
	if err != nil {
		t.Fatalf("ResolveIdentityProfile: %v", err)
	}
	if profile.Username != "alice" || profile.Password != "alice-password" {
		t.Errorf("credentials not overridden: %+v", profile)
	}
	if profile.UsernameField != "email" || profile.SuccessTextContains != "Welcome" {
		t.Errorf("mechanism fields not inherited from the referenced profile: %+v", profile)
	}
	if profile.Host != "app.test" {
		t.Errorf("Host = %q, want app.test (inherited from the profile's own login_url)", profile.Host)
	}
}

func TestResolveIdentityProfile_NoOverride_UsesProfileDefaults(t *testing.T) {
	t.Setenv("SHARED_USER", "shared-default-user")
	t.Setenv("SHARED_PASS", "shared-default-pass")
	profiles := []ProfileConfig{{
		Name: "single-account-login", Type: TypeFormLogin,
		LoginURL: "http://app.test/login", UsernameEnv: "SHARED_USER", PasswordEnv: "SHARED_PASS",
	}}
	ic := IdentityConfig{Name: "only-account", AuthProfile: "single-account-login"}
	profile, err := ResolveIdentityProfile(ic, profiles)
	if err != nil {
		t.Fatalf("ResolveIdentityProfile: %v", err)
	}
	if profile.Username != "shared-default-user" {
		t.Errorf("Username = %q, want the profile's own default when the identity supplies no override", profile.Username)
	}
}

func TestResolveIdentityProfile_UnknownAuthProfile_Fails(t *testing.T) {
	ic := IdentityConfig{Name: "account-a", AuthProfile: "does-not-exist"}
	_, err := ResolveIdentityProfile(ic, nil)
	if err == nil || !strings.Contains(err.Error(), "account-a") {
		t.Fatalf("expected an error naming the identity, got: %v", err)
	}
}

func TestResolveIdentityProfile_TwoIdentities_SameProfile_IndependentCredentials(t *testing.T) {
	t.Setenv("SHARED_USER", "shared")
	t.Setenv("SHARED_PASS", "shared-pass")
	t.Setenv("USER_A", "alice")
	t.Setenv("PASS_A", "alice-pass")
	t.Setenv("USER_B", "bob")
	t.Setenv("PASS_B", "bob-pass")

	profiles := []ProfileConfig{{
		Name: "customer-login", Type: TypeFormLogin, LoginURL: "http://app.test/login",
		UsernameEnv: "SHARED_USER", PasswordEnv: "SHARED_PASS",
	}}
	profileA, err := ResolveIdentityProfile(IdentityConfig{Name: "account-a", AuthProfile: "customer-login", UsernameEnv: "USER_A", PasswordEnv: "PASS_A"}, profiles)
	if err != nil {
		t.Fatalf("resolve account-a: %v", err)
	}
	profileB, err := ResolveIdentityProfile(IdentityConfig{Name: "account-b", AuthProfile: "customer-login", UsernameEnv: "USER_B", PasswordEnv: "PASS_B"}, profiles)
	if err != nil {
		t.Fatalf("resolve account-b: %v", err)
	}
	if profileA.Username == profileB.Username {
		t.Fatal("two identities sharing one auth profile must resolve to DIFFERENT credentials when each overrides its own")
	}
	if profileA.Username != "alice" || profileB.Username != "bob" {
		t.Errorf("unexpected credentials: A=%q B=%q", profileA.Username, profileB.Username)
	}
}
