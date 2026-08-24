package auth

import (
	"strings"
	"testing"
	"time"
)

func TestResolveProfile_FormLogin_Valid(t *testing.T) {
	t.Setenv("SAKANNER_TEST_USER", "alice")
	t.Setenv("SAKANNER_TEST_PASS", "s3cret")

	p, err := ResolveProfile(ProfileConfig{
		Name: "lab", Type: TypeFormLogin,
		LoginURL: "http://app.test/login", UsernameEnv: "SAKANNER_TEST_USER", PasswordEnv: "SAKANNER_TEST_PASS",
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if p.Username != "alice" || p.Password != "s3cret" {
		t.Fatalf("credentials not resolved from env: %+v", p)
	}
	if p.Host != "app.test" {
		t.Errorf("Host = %q, want app.test (derived from login_url)", p.Host)
	}
	if p.UsernameField != "username" || p.PasswordField != "password" {
		t.Errorf("field defaults not applied: %+v", p)
	}
	if p.Timeout != DefaultTimeout || p.MaxRedirects != DefaultMaxRedirects {
		t.Errorf("defaults not applied: timeout=%v maxRedirects=%d", p.Timeout, p.MaxRedirects)
	}
}

func TestResolveProfile_FormLogin_CustomFieldsAndScopeHostOverride(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	p, err := ResolveProfile(ProfileConfig{
		Name: "x", Type: TypeFormLogin,
		LoginURL: "https://login.app.test/auth", UsernameEnv: "U", PasswordEnv: "P",
		UsernameField: "email", PasswordField: "pass", ScopeHost: "app.test",
		Timeout: 3 * time.Second, MaxRedirects: 2,
	})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if p.UsernameField != "email" || p.PasswordField != "pass" {
		t.Errorf("custom field names not honored: %+v", p)
	}
	if p.Host != "app.test" {
		t.Errorf("Host = %q, want app.test (explicit scope_host overrides login_url host)", p.Host)
	}
	if p.Timeout != 3*time.Second || p.MaxRedirects != 2 {
		t.Errorf("explicit timeout/max_redirects not honored: %+v", p)
	}
}

func TestResolveProfile_FormLogin_MissingEnvVars_CombinedError(t *testing.T) {
	_, err := ResolveProfile(ProfileConfig{
		Name: "lab", Type: TypeFormLogin, LoginURL: "http://app.test/login",
		UsernameEnv: "SAKANNER_DOES_NOT_EXIST_USER", PasswordEnv: "SAKANNER_DOES_NOT_EXIST_PASS",
	})
	if err == nil {
		t.Fatal("expected an error for two missing env vars")
	}
	for _, want := range []string{"SAKANNER_DOES_NOT_EXIST_USER", "SAKANNER_DOES_NOT_EXIST_PASS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q (both problems should be reported together): %v", want, err)
		}
	}
}

func TestResolveProfile_FormLogin_MissingLoginURL(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	_, err := ResolveProfile(ProfileConfig{Name: "lab", Type: TypeFormLogin, UsernameEnv: "U", PasswordEnv: "P"})
	if err == nil || !strings.Contains(err.Error(), "login_url") {
		t.Fatalf("expected a login_url error, got: %v", err)
	}
}

func TestResolveProfile_FormLogin_InvalidLoginURL(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	for _, bad := range []string{"not a url", "ftp://app.test/login", "javascript:alert(1)", "/relative/only"} {
		_, err := ResolveProfile(ProfileConfig{Name: "lab", Type: TypeFormLogin, LoginURL: bad, UsernameEnv: "U", PasswordEnv: "P"})
		if err == nil {
			t.Errorf("login_url %q: expected an error, got none", bad)
		}
	}
}

func TestResolveProfile_UnknownType(t *testing.T) {
	_, err := ResolveProfile(ProfileConfig{Name: "x", Type: "not_a_real_type"})
	if err == nil || !strings.Contains(err.Error(), "unknown authentication type") {
		t.Fatalf("expected an unknown-type error, got: %v", err)
	}
}

func TestResolveProfile_EmptyName(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	_, err := ResolveProfile(ProfileConfig{Type: TypeFormLogin, LoginURL: "http://app.test/login", UsernameEnv: "U", PasswordEnv: "P"})
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("expected a name error, got: %v", err)
	}
}

func TestResolveProfile_NegativeMaxRedirects(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	_, err := ResolveProfile(ProfileConfig{Name: "x", Type: TypeFormLogin, LoginURL: "http://app.test/login", UsernameEnv: "U", PasswordEnv: "P", MaxRedirects: -1})
	if err == nil || !strings.Contains(err.Error(), "max_redirects") {
		t.Fatalf("expected a max_redirects error, got: %v", err)
	}
}

func TestResolveProfile_Cookie_Valid(t *testing.T) {
	t.Setenv("SESS", "session_id=abc123; Path=/")
	p, err := ResolveProfile(ProfileConfig{Name: "c", Type: TypeCookie, CookieEnv: "SESS", ScopeHost: "app.test"})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if p.CookieHeader != "session_id=abc123; Path=/" || p.Host != "app.test" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestResolveProfile_Cookie_MissingScopeHost(t *testing.T) {
	t.Setenv("SESS", "session_id=abc123")
	_, err := ResolveProfile(ProfileConfig{Name: "c", Type: TypeCookie, CookieEnv: "SESS"})
	if err == nil || !strings.Contains(err.Error(), "scope_host") {
		t.Fatalf("expected a scope_host error, got: %v", err)
	}
}

func TestResolveProfile_Cookie_MissingEnv(t *testing.T) {
	_, err := ResolveProfile(ProfileConfig{Name: "c", Type: TypeCookie, ScopeHost: "app.test"})
	if err == nil || !strings.Contains(err.Error(), "cookie_env") {
		t.Fatalf("expected a cookie_env error, got: %v", err)
	}
}

func TestResolveProfile_BearerToken_Valid(t *testing.T) {
	t.Setenv("TOK", "abc.def.ghi")
	p, err := ResolveProfile(ProfileConfig{Name: "b", Type: TypeBearerToken, TokenEnv: "TOK", ScopeHost: "api.test"})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if p.Token != "abc.def.ghi" || p.Host != "api.test" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestResolveProfile_Header_Valid(t *testing.T) {
	t.Setenv("HV", "secret-header-value")
	p, err := ResolveProfile(ProfileConfig{Name: "h", Type: TypeHeader, HeaderName: "X-Api-Key", HeaderValueEnv: "HV", ScopeHost: "api.test"})
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if p.HeaderName != "X-Api-Key" || p.HeaderValue != "secret-header-value" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestResolveProfile_Header_MissingHeaderName(t *testing.T) {
	t.Setenv("HV", "v")
	_, err := ResolveProfile(ProfileConfig{Name: "h", Type: TypeHeader, HeaderValueEnv: "HV", ScopeHost: "api.test"})
	if err == nil || !strings.Contains(err.Error(), "header_name") {
		t.Fatalf("expected a header_name error, got: %v", err)
	}
}

func TestResolveProfile_EmptyEnvVarValue_TreatedAsMissing(t *testing.T) {
	t.Setenv("EMPTY_TOKEN", "")
	_, err := ResolveProfile(ProfileConfig{Name: "b", Type: TypeBearerToken, TokenEnv: "EMPTY_TOKEN", ScopeHost: "api.test"})
	if err == nil || !strings.Contains(err.Error(), "EMPTY_TOKEN") {
		t.Fatalf("an env var set to the empty string must be treated as missing, got: %v", err)
	}
}

func TestResolveProfile_Deterministic(t *testing.T) {
	t.Setenv("U", "u")
	t.Setenv("P", "p")
	pc := ProfileConfig{Name: "x", Type: TypeFormLogin, LoginURL: "http://app.test/login", UsernameEnv: "U", PasswordEnv: "P"}
	p1, err1 := ResolveProfile(pc)
	p2, err2 := ResolveProfile(pc)
	if err1 != nil || err2 != nil {
		t.Fatalf("errs: %v %v", err1, err2)
	}
	if p1.Host != p2.Host || p1.Username != p2.Username || p1.Timeout != p2.Timeout {
		t.Errorf("ResolveProfile is not deterministic: %+v vs %+v", p1, p2)
	}
}

func TestFindProfileConfig(t *testing.T) {
	profiles := []ProfileConfig{{Name: "a"}, {Name: "b"}}
	if _, err := FindProfileConfig(profiles, "a"); err != nil {
		t.Errorf("expected to find %q: %v", "a", err)
	}
	_, err := FindProfileConfig(profiles, "missing")
	if err == nil {
		t.Fatal("expected an UnknownProfileError")
	}
	upErr, ok := err.(*UnknownProfileError)
	if !ok {
		t.Fatalf("error type = %T, want *UnknownProfileError", err)
	}
	if len(upErr.Available) != 2 || upErr.Available[0] != "a" || upErr.Available[1] != "b" {
		t.Errorf("Available = %v, want sorted [a b]", upErr.Available)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error message missing profile name: %v", err)
	}
}

func TestFindProfileConfig_NoneConfigured(t *testing.T) {
	_, err := FindProfileConfig(nil, "anything")
	if err == nil || !strings.Contains(err.Error(), "none configured") {
		t.Fatalf("expected a 'none configured' hint, got: %v", err)
	}
}
