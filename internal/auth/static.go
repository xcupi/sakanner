package auth

import (
	"context"
	"fmt"
	"time"
)

// StaticProvider implements Provider for the three authentication
// types that need no login request of their own: the operator already
// holds a valid credential (a session cookie, a bearer/API token, or a
// custom header value) and this Provider simply builds a Session that
// carries it. No network activity of its own -- only a scope check on
// the configured host, so a static credential can never be used against
// a host authentication was never authorized to touch either (task
// section 8 applies uniformly across all four types, not just
// form_login).
type StaticProvider struct {
	Profile Profile
}

func (sp *StaticProvider) Authenticate(ctx context.Context, deps Dependencies) (*Session, error) {
	p := sp.Profile
	sess := &Session{ProfileName: p.Name, Type: p.Type, Host: p.Host, State: StateAuthenticating, CreatedAt: time.Now().UTC()}

	if deps.Validator != nil {
		decision, err := deps.Validator.CheckHost(ctx, p.Host)
		if err != nil {
			return failSession(sess, fmt.Errorf("auth: scope check for %q: %w", p.Host, err))
		}
		if !decision.Allowed {
			return failSession(sess, fmt.Errorf("auth: profile %q's host %q is out of scope", p.Name, p.Host))
		}
	}

	sess.Headers = map[string]string{}
	switch p.Type {
	case TypeCookie:
		sess.Headers["Cookie"] = p.CookieHeader
	case TypeBearerToken:
		sess.Headers["Authorization"] = "Bearer " + p.Token
	case TypeHeader:
		sess.Headers[p.HeaderName] = p.HeaderValue
	default:
		return failSession(sess, fmt.Errorf("auth: StaticProvider does not support type %q", p.Type))
	}

	sess.State = StateAuthenticated
	return sess, nil
}

// failSession marks sess StateFailed with a secret-free reason derived
// from err, and returns it alongside err -- shared by every Provider so
// a failed authentication attempt always produces a fully-populated,
// non-nil Session (never a nil Session forcing every caller to nil-check
// before it can even report what went wrong).
func failSession(sess *Session, err error) (*Session, error) {
	sess.State = StateFailed
	sess.FailureReason = err.Error()
	return sess, err
}
