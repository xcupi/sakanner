package auth

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sakanner/internal/safedial"
)

// CookiesFor returns the cookies s holds for host, or nil if s is nil,
// carries no cookie jar (every Type except a successful TypeFormLogin),
// or host does not match s.Host.
//
// The host check is deliberate and load-bearing, not defensive
// decoration: it is what stops a caller that (by mistake, or via a
// future bug elsewhere) asks for "this session's cookies" while
// building a request to a DIFFERENT host from ever receiving them at
// this layer, independent of whatever internal/scope/safedial dial-time
// enforcement would separately also catch (task section 8's "cookie
// sent to wrong host" -- defense in depth, not the only layer). scheme
// matters because a Secure-flagged cookie is only ever released for
// "https".
func (s *Session) CookiesFor(scheme, host string) []*http.Cookie {
	if s == nil || s.Jar == nil || host == "" || !strings.EqualFold(host, s.Host) {
		return nil
	}
	u := &url.URL{Scheme: scheme, Host: host, Path: "/"}
	return s.Jar.Cookies(u)
}

// HeadersFor returns a copy of s's static headers (Authorization,
// Cookie, or a custom header name) if host matches s.Host, or nil
// otherwise -- the same host-pinning guarantee CookiesFor documents,
// applied to headers (task section 8's "Authorization header leakage").
// A copy is returned so a caller mutating the result never affects s.
func (s *Session) HeadersFor(host string) map[string]string {
	if s == nil || len(s.Headers) == 0 || host == "" || !strings.EqualFold(host, s.Host) {
		return nil
	}
	out := make(map[string]string, len(s.Headers))
	for k, v := range s.Headers {
		out[k] = v
	}
	return out
}

// JarFor returns s's own cookie jar if host matches s.Host, or nil
// otherwise -- the SAME host-pinning guarantee CookiesFor/HeadersFor
// document, applied to the raw jar handed to a caller (Phase 3.15's
// internal/crawler, which needs the live jar itself -- not a
// point-in-time snapshot of Cookies() -- so cookies the crawl itself
// receives, e.g. a session-refresh Set-Cookie, are captured back into
// the session as the crawl progresses, exactly as a real browser's
// cookie jar would evolve). The returned jar is the session's own
// live object, not a copy: net/http/cookiejar.Jar's SetCookies/Cookies
// are documented safe for concurrent use, so sharing it across the
// concurrent per-target crawl goroutines of ONE scan is safe; sharing
// it ACROSS scans never happens, since every Provider.Authenticate call
// builds its own fresh jar (see formlogin.go) -- no two Session values
// ever point at the same jar.
func (s *Session) JarFor(host string) http.CookieJar {
	if s == nil || s.Jar == nil || host == "" || !strings.EqualFold(host, s.Host) {
		return nil
	}
	return s.Jar
}

// NewClient builds an *http.Client for hostname/ip via dialer (the same
// scope-safe dialing every other stage of this codebase uses -- see
// internal/safedial's package doc), with s's cookies/headers attached
// ONLY when hostname matches s.Host. Calling this for a session-Host
// mismatch is not an error: it simply returns a plain, unauthenticated
// client, identical to what the caller would get by passing a nil
// Session -- the caller is never blocked from making an unauthenticated
// request to a different host, it just never carries this session's
// credentials there.
//
// Header pinning is delegated to safedial.PinnedRoundTripper -- see its
// doc comment for why a per-request (not per-client) host check is
// required, not merely a nicety.
func (s *Session) NewClient(dialer *safedial.Dialer, hostname string, ip net.IP, timeout time.Duration, maxRedirects int) *http.Client {
	client := dialer.NewClient(hostname, ip, nil, nil, timeout, maxRedirects)
	if s == nil {
		return client
	}
	if s.Jar != nil && strings.EqualFold(hostname, s.Host) {
		client.Jar = s.Jar
	}
	if len(s.Headers) > 0 {
		client.Transport = &safedial.PinnedRoundTripper{Base: client.Transport, Headers: s.Headers, PinnedHost: s.Host}
	}
	return client
}
