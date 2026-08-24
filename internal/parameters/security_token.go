package parameters

import "strings"

// securityTokenFieldNames is an exact-match, case-insensitive list of
// common CSRF/anti-forgery field names -- deliberately a SEPARATE list
// from internal/evidence.sensitiveFieldNames, which exists to decide
// what gets value-REDACTED (a narrower, exact-match-only concern).
// This one exists to decide what should never be independently offered
// as an active-mutation target (a slightly broader net is fine here:
// a false positive just means one field is never fuzzed on its own,
// not a detection-completeness regression this phase is trying to
// close -- see docs/phase-3-21-form-mutation.md section 2).
var securityTokenFieldNames = map[string]bool{
	"csrf":                     true,
	"csrf_token":               true,
	"xsrf":                     true,
	"xsrf_token":               true,
	"authenticity_token":       true,
	"nonce":                    true,
	"requestverificationtoken": true,
	"anti_csrf":                true,
	"antiforgerytoken":         true,
}

// IsLikelySecurityToken conservatively reports whether name looks like
// a CSRF/anti-forgery/security-token field -- name-based only, never
// derived from a field's Value or its Hidden status (a security token
// is not always hidden, and a hidden field is not always a security
// token; see models.Parameter.Hidden's own doc comment). Used by
// BuildTargets to exclude a field from becoming its OWN active-
// mutation Target while still including it in a form's FormFields
// baseline (task section 7: "preserve these fields ... unless the
// selected mutation target is explicitly that field").
func IsLikelySecurityToken(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if securityTokenFieldNames[n] {
		return true
	}
	return strings.Contains(n, "csrf") ||
		strings.Contains(n, "xsrf") ||
		strings.Contains(n, "verificationtoken") ||
		strings.HasSuffix(n, "_token")
}
