// Package auth is sakanner's Phase 3.14 authentication/session
// foundation: a small, self-contained layer that turns a named
// AuthProfile into an authenticated Session the rest of the scanner can
// use without knowing how authentication was performed.
//
//	Authentication configuration (ProfileConfig)
//	        |
//	        v  ResolveProfile (env-var secret resolution, validation)
//	Authentication profile (Profile)
//	        |
//	        v  NewProvider + Provider.Authenticate
//	Authenticated session/context (Session)
//	        |
//	        v  Session.CookiesFor / Session.HeadersFor / Session.NewClient
//	Crawler / HTTP client / detectors
//
// Four authentication types are supported: form-based username/password
// login (TypeFormLogin, the only type that performs a login flow of its
// own), and three "static" types that require no login request at all
// because the operator already holds a valid credential -- an HTTP
// session cookie (TypeCookie), a bearer/API token (TypeBearerToken), or
// a custom authentication header (TypeHeader).
//
// This package deliberately does NOT implement: JSON login, browser-
// based authentication, OAuth/OIDC, CSRF-protected multi-step login
// flows beyond preserving a login form's own hidden fields verbatim,
// MFA-assisted/manual authentication, credential brute forcing/
// spraying/stuffing, CAPTCHA/MFA bypass, or any other authentication
// BYPASS technique. See docs/phase-3-14-authentication.md "Limitations
// and explicitly out of scope" for the full list and the architecture
// left open for each of these as future work.
//
// Scope enforcement: every network request this package makes --
// resolving the login host, dialing it, following a redirect, following
// the login form's own action URL -- goes through the exact same
// internal/scope.Validator and internal/safedial.Dialer every other
// network-touching package in this codebase already uses. This package
// introduces no new scope-validation logic; see
// docs/phase-3-14-authentication.md "Scope enforcement" for exactly
// which existing mechanism covers which adversarial scenario.
//
// Secrets: a Profile's resolved Username/Password/Token/HeaderValue/
// CookieHeader fields, and a Session's cookies/headers, are held only in
// memory for the lifetime of one scan process. Nothing in this package
// logs, persists, or includes a secret value in any returned error --
// see redact.go and docs/phase-3-14-authentication.md "Secret handling"
// for the specific mechanisms and reused conventions (this package
// reuses internal/evidence's own redaction blocklist rather than
// maintaining a second one).
package auth
