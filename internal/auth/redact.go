package auth

import "sakanner/internal/evidence"

// RedactedPlaceholder reuses internal/evidence's own established
// redaction convention (task section 6's "existing evidence redaction
// mechanisms must be reused where possible") rather than inventing a
// second "<REDACTED>"-shaped literal that could drift from it --
// exported so cmd/scanner's display code can render a
// ProfileSummary/SessionSummary's boolean Has*/CookieCount fields as
// this exact string without importing internal/evidence itself just
// for this one constant.
const RedactedPlaceholder = evidence.RedactedPlaceholder

// ProfileSummary is a secret-free view of a Profile, safe to print
// (`scanner auth profiles show`) or log -- every credential field is
// reduced to a boolean (HasUsername, HasPassword, ...); the caller
// renders a set one as RedactedPlaceholder and an unset one as "(not
// configured)" or similar -- the real value is never held anywhere in
// this struct.
type ProfileSummary struct {
	Name           string
	Type           Type
	Host           string
	LoginURL       string // safe: a URL, not a secret -- userinfo is still stripped defensively, see Redacted below
	StartURL       string // TypeFormLoginAuto only -- the discovery starting point; empty for every other type
	UsernameField  string
	PasswordField  string
	HasUsername    bool
	HasPassword    bool
	HasToken       bool
	HasCookie      bool
	HeaderName     string
	HasHeaderValue bool
	Timeout        string
	MaxRedirects   int
}

// Redacted returns a secret-free summary of p -- the only form of a
// Profile's own credential state this package ever exposes for display.
func (p Profile) Redacted() ProfileSummary {
	loginURL := ""
	if p.LoginURL != nil {
		u := *p.LoginURL
		u.User = nil // defense in depth: strip any userinfo even though ResolveProfile never sets one from a secret
		loginURL = u.String()
	}
	startURL := ""
	if p.StartURL != nil {
		u := *p.StartURL
		u.User = nil
		startURL = u.String()
	}
	return ProfileSummary{
		Name:           p.Name,
		Type:           p.Type,
		Host:           p.Host,
		LoginURL:       loginURL,
		StartURL:       startURL,
		UsernameField:  p.UsernameField,
		PasswordField:  p.PasswordField,
		HasUsername:    p.Username != "",
		HasPassword:    p.Password != "",
		HasToken:       p.Token != "",
		HasCookie:      p.CookieHeader != "",
		HeaderName:     p.HeaderName,
		HasHeaderValue: p.HeaderValue != "",
		Timeout:        p.Timeout.String(),
		MaxRedirects:   p.MaxRedirects,
	}
}

// SessionSummary is a secret-free view of a Session -- cookie/header
// VALUES never appear, only counts and names, matching task section
// 6's "never log session cookies, never log Authorization headers."
type SessionSummary struct {
	ProfileName   string
	IdentityName  string
	Type          Type
	State         State
	Host          string
	CookieCount   int
	HeaderNames   []string // names only, never values
	CreatedAt     string
	FailureReason string
}

// Redacted returns a secret-free summary of s.
func (s *Session) Redacted() SessionSummary {
	if s == nil {
		return SessionSummary{State: StateUnauthenticated}
	}
	var headerNames []string
	for k := range s.Headers {
		headerNames = append(headerNames, k)
	}
	cookieCount := 0
	if s.Jar != nil && s.Host != "" {
		// "https" is queried (not "http") because it is the superset:
		// cookiejar returns every cookie for the host regardless of its
		// own Secure attribute when asked with an https:// URL, while an
		// http:// query would exclude Secure-flagged cookies -- querying
		// both and summing would double-count the non-Secure ones.
		cookieCount = len(s.CookiesFor("https", s.Host))
	}
	return SessionSummary{
		ProfileName:   s.ProfileName,
		IdentityName:  s.IdentityName,
		Type:          s.Type,
		State:         s.State,
		Host:          s.Host,
		CookieCount:   cookieCount,
		HeaderNames:   headerNames,
		CreatedAt:     s.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		FailureReason: s.FailureReason,
	}
}
