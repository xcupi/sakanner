package parameters

import "testing"

func TestIsLikelySecurityToken_KnownNames(t *testing.T) {
	for _, name := range []string{
		"csrf", "csrf_token", "CSRF_TOKEN", "xsrf", "xsrf_token",
		"authenticity_token", "nonce", "requestverificationtoken",
		"__RequestVerificationToken", "anti_csrf", "antiforgerytoken",
		"my_csrf_field", "session_token", "form_token",
	} {
		if !IsLikelySecurityToken(name) {
			t.Errorf("IsLikelySecurityToken(%q) = false, want true", name)
		}
	}
}

func TestIsLikelySecurityToken_OrdinaryFieldNames(t *testing.T) {
	for _, name := range []string{
		"username", "email", "display_name", "category", "id",
		"comment", "theme", "visibility", "newsletter", "",
	} {
		if IsLikelySecurityToken(name) {
			t.Errorf("IsLikelySecurityToken(%q) = true, want false", name)
		}
	}
}

func TestIsLikelySecurityToken_WhitespaceTrimmedCaseInsensitive(t *testing.T) {
	if !IsLikelySecurityToken("  Csrf_Token  ") {
		t.Error("expected whitespace-padded, mixed-case csrf_token to match")
	}
}
