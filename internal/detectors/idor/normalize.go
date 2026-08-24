package idor

import (
	"bytes"
	"strings"
)

// normalizeBody strips deterministic-but-varying dynamic content (any
// run of ASCII digits, collapsed to "#") before comparing two
// responses -- the same normalization sqli/ssrf already established,
// for the identical reason (a timestamp/counter must not be mistaken
// for a real content difference).
func normalizeBody(body []byte) string {
	var b strings.Builder
	b.Grow(len(body))
	inDigits := false
	for _, r := range string(body) {
		if r >= '0' && r <= '9' {
			if !inDigits {
				b.WriteByte('#')
				inDigits = true
			}
			continue
		}
		inDigits = false
		b.WriteRune(r)
	}
	return b.String()
}

// looksAllowed reports whether a response represents genuine access to
// something (2xx status with a non-empty body) as opposed to a denial
// (401/403/404/anything else) or an empty response. This is
// deliberately simple and general -- it does not try to parse or
// understand the body's content, only whether the server's own status
// line indicates success.
func looksAllowed(statusCode int, body []byte) bool {
	return statusCode >= 200 && statusCode < 300 && len(bytes.TrimSpace(body)) > 0
}

// isResourceSpecific reports whether body appears to actually reflect
// the specific resource that was requested -- i.e. it contains the
// requested identifier somewhere in its own content. A response that
// does NOT vary by identifier (a constant "status: ok"-shaped body
// regardless of which resource was asked for) can never be trusted as
// evidence that a SPECIFIC protected object was returned, no matter
// what identity requested it or what status code came back -- see
// docs/phase-3-5-idor-bola.md "Response validation" for the false
// positive this specifically prevents (task section 14: "a generic
// success page" / "only HTTP status differs without protected-resource
// evidence").
func isResourceSpecific(body []byte, id string) bool {
	return id != "" && bytes.Contains(body, []byte(id))
}
