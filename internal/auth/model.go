package auth

import (
	"net/http"
	"net/url"
	"time"
)

// Type identifies an authentication mechanism. Section 1's minimum
// required set -- form-based login, HTTP session cookies, bearer/API
// tokens, and custom headers -- exhausts the constants below; adding a
// future mechanism (JSON login, OAuth/OIDC, browser-based auth) means
// adding one more constant plus one more Provider implementation, never
// changing this type's shape or any existing caller.
type Type string

const (
	TypeFormLogin   Type = "form_login"
	TypeCookie      Type = "cookie"
	TypeBearerToken Type = "bearer_token"
	TypeHeader      Type = "header"
)

// Valid reports whether t is one of this build's known authentication
// types.
func (t Type) Valid() bool {
	switch t {
	case TypeFormLogin, TypeCookie, TypeBearerToken, TypeHeader:
		return true
	default:
		return false
	}
}

// State is one of section 7's explicit authentication lifecycle states
// -- deliberately its own type, never conflated with
// internal/orchestrator's Status/DetectionState enums (a scan's overall
// outcome and its authentication outcome are different, independently
// meaningful facts; see docs/phase-3-14-authentication.md
// "Authentication state vs. scan status").
type State string

const (
	// StateUnauthenticated is a Session's zero-value-equivalent state
	// and the state a scan reports when no --auth-profile was given at
	// all -- "scan completed without authentication," never confused
	// with a failed authentication ATTEMPT.
	StateUnauthenticated State = "UNAUTHENTICATED"
	// StateAuthenticating is set on the in-progress Session a Provider
	// builds before its login flow completes -- observable by a caller
	// that inspects a Session mid-Authenticate (e.g. in tests), never
	// returned as a Session's FINAL state by a Provider.
	StateAuthenticating State = "AUTHENTICATING"
	// StateAuthenticated means the login (or static-credential setup)
	// succeeded and the Session is ready to use.
	StateAuthenticated State = "AUTHENTICATED"
	// StateFailed means authentication was attempted and did not
	// succeed -- wrong credentials, an out-of-scope host, a network/
	// timeout error, or a response that failed the configured/default
	// success check. FailureReason carries the (secret-free) detail.
	StateFailed State = "AUTHENTICATION_FAILED"
	// StateExpired is set by a caller that determines an
	// already-AUTHENTICATED Session's ExpiresAt has passed -- this
	// package never sets it itself (no mechanism here re-checks a
	// live Session's freshness), but the state exists so callers that
	// track session age have a defined vocabulary rather than
	// inventing their own. See Session.IsExpired.
	StateExpired State = "AUTHENTICATION_EXPIRED"
	// StateUnknown is for a Session whose validity cannot currently be
	// determined (e.g. persisted/reloaded session state with no
	// verification performed yet) -- not used by any Provider in this
	// build, reserved for future session-persistence work.
	StateUnknown State = "AUTHENTICATION_UNKNOWN"
)

// ProfileConfig is the raw, not-yet-secret-resolved shape of one
// authentication profile as loaded from configuration -- mirrors
// internal/policy's ConfigView pattern: this package defines its own
// config-shaped view rather than importing internal/config, so
// internal/config may depend on this package's types without any
// import cycle, and this package stays testable with plain literals.
// See internal/config.AuthProfileConfig for the mapstructure-tagged
// twin cmd/scanner translates field-by-field into this type.
type ProfileConfig struct {
	Name string
	Type Type

	// FORM_LOGIN fields (task section 4).
	LoginURL      string
	UsernameEnv   string
	PasswordEnv   string
	UsernameField string            // form field name for the username; defaults to "username" if empty
	PasswordField string            // form field name for the password; defaults to "password" if empty
	ExtraFields   map[string]string // additional static, non-secret form fields to submit/override (e.g. "remember_me": "1")

	// Success/failure indicators (task section 4's "configurable
	// success/failure indicators"). All empty means the built-in
	// heuristic (see evaluateSuccess) applies.
	SuccessURLContains  string // final response URL must contain this substring
	SuccessTextContains string // response body must contain this substring
	FailureTextContains string // response body must NOT contain this substring

	// COOKIE fields.
	CookieEnv string // env var holding a raw "name=value; name2=value2" Cookie header

	// BEARER_TOKEN fields.
	TokenEnv string // env var holding the bearer token (sent as "Authorization: Bearer <token>")

	// HEADER fields.
	HeaderName     string // the custom header's name
	HeaderValueEnv string // env var holding the header's value

	// ScopeHost is the host this session is authorized for -- required
	// for TypeCookie/TypeBearerToken/TypeHeader (which have no login
	// URL to derive a host from); optional for TypeFormLogin, where it
	// defaults to the login URL's own host and only needs to be set
	// explicitly if the profile intentionally pins the session to a
	// DIFFERENT host than the login URL's.
	ScopeHost string

	Timeout      time.Duration // 0 => DefaultTimeout
	MaxRedirects int           // 0 => DefaultMaxRedirects; negative is invalid
}

// DefaultTimeout/DefaultMaxRedirects are applied by ResolveProfile
// whenever a ProfileConfig leaves Timeout/MaxRedirects unset (the zero
// value) -- a resolved Profile always carries concrete, bounded values,
// mirroring internal/policy.Profile's own "never leave a zero value
// that could be misread as unlimited" convention.
const (
	DefaultTimeout      = 15 * time.Second
	DefaultMaxRedirects = 5
)

// Profile is a fully resolved authentication profile -- every secret
// reference in a ProfileConfig has already been read from its
// environment variable and validated. A Profile is safe to hold in
// memory for the duration of one scan process; it is never persisted or
// logged in full (see redact.go).
type Profile struct {
	Name string
	Type Type
	// Host is the hostname this profile's Session is authorized for --
	// the scope anchor every request this package makes, and every
	// header/cookie Session.CookiesFor/HeadersFor releases, is pinned
	// to. Derived from LoginURL for TypeFormLogin (unless ScopeHost
	// overrides it), or taken directly from ScopeHost for the three
	// static types.
	Host string

	// Resolved secrets -- populated only for the fields this Profile's
	// Type actually uses; never logged, never included in an error
	// message (see redact.go's Profile.Redacted).
	Username     string
	Password     string
	Token        string
	HeaderName   string
	HeaderValue  string
	CookieHeader string

	// FORM_LOGIN fields.
	LoginURL      *url.URL
	UsernameField string
	PasswordField string
	ExtraFields   map[string]string

	SuccessURLContains  string
	SuccessTextContains string
	FailureTextContains string

	Timeout      time.Duration
	MaxRedirects int
}

// Session is an authenticated context the rest of the scanner can reuse
// without knowing how authentication was performed (task section 5).
// Detectors and every other consumer only ever see cookies/headers
// through CookiesFor/HeadersFor/NewClient -- never Profile's own
// credentials.
type Session struct {
	ProfileName string
	// IdentityName is Phase 3.16's own addition -- the CONFIGURED
	// IDENTITY name this session was authenticated for (e.g.
	// "account-a"), distinct from ProfileName (the underlying auth
	// profile's own name, e.g. "customer-login" -- see
	// docs/phase-3-16-multi-identity.md "Auth Profile vs. Identity").
	// Empty for a session authenticated directly via --auth-profile
	// with no identity wrapper (Phase 3.14/3.15's original path,
	// unchanged) -- never populated by internal/auth itself, only by a
	// caller (cmd/scanner) that resolved an Identity. Not a secret: an
	// identity label is an operator-chosen name, safe for CLI/report
	// output, exactly like ProfileName already is.
	IdentityName string
	Type         Type
	State        State
	// Host is the single host this Session's cookies/headers are ever
	// released for -- see CookiesFor/HeadersFor's host-pinning doc
	// comments for why this is the primary anti-leakage mechanism at
	// the data-access layer, on top of internal/scope's own dial-time
	// enforcement.
	Host string

	// Jar holds cookies captured during a form_login flow (nil for
	// every other Type). A standard net/http/cookiejar.Jar is used
	// deliberately: its RFC 6265 domain-matching is what guarantees a
	// cookie set by one host is never handed back for another, without
	// this package re-implementing that matching logic itself.
	Jar http.CookieJar

	// LoginURL is set only for a TypeFormLogin session (nil otherwise).
	// Phase 3.15 originally used this to recognize "a crawled page's
	// final URL IS the login page again" as a session-expiration
	// signal, but that heuristic was removed after it produced a false
	// positive (an authenticated crawl simply following an ORDINARY
	// link to the login page -- not a redirect caused by expiration --
	// was wrongly flagged; see
	// internal/orchestration/pipeline.go's detectSessionExpired doc
	// comment for the full account). The field remains: it is harmless,
	// not a secret (a login URL is operator-supplied configuration,
	// already visible via `scanner auth profiles show`), and a future,
	// more precise implementation that also tracks each crawled page's
	// PRE-redirect requested path could use it correctly.
	LoginURL *url.URL

	// Headers are static headers attached to every in-scope request --
	// "Cookie" for TypeCookie, "Authorization" for TypeBearerToken, or
	// the operator-named header for TypeHeader/a form_login profile's
	// own ExtraFields never populate this (form_login's state lives in
	// Jar instead).
	Headers map[string]string

	CreatedAt time.Time
	// ExpiresAt is nil unless a mechanism that knows a concrete
	// expiry sets it -- no Provider in this build populates it (task
	// section 5's "expiration metadata if known" -- none of the four
	// supported types carries a machine-readable expiry the scanner
	// can observe), reserved for future providers (e.g. a JWT bearer
	// token with a parseable "exp" claim) that do.
	ExpiresAt *time.Time

	// FailureReason is set when State == StateFailed -- a short,
	// secret-free human-readable reason (status code, "no session
	// cookie was established", "host is out of scope", ...), never the
	// raw response body or any credential value.
	FailureReason string
}

// IsExpired reports whether s carries a known expiry that has passed as
// of now. A Session with no known expiry (ExpiresAt == nil, true for
// every Session this package's Providers currently produce) is never
// considered expired by this method -- callers that need staleness
// bounds regardless of a concrete expiry should compare CreatedAt
// themselves.
func (s *Session) IsExpired(now time.Time) bool {
	if s == nil || s.ExpiresAt == nil {
		return false
	}
	return now.After(*s.ExpiresAt)
}
