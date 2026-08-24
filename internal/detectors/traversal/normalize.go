package traversal

import (
	"bytes"
	"html"
	"net/url"
	"strings"
)

// normalizeBody strips deterministic-but-varying dynamic content (any
// run of ASCII digits, collapsed to "#") before comparing two
// responses -- the same normalization sqli/ssrf/idor already
// established, for the identical reason (a timestamp/counter must not
// be mistaken for a real content difference).
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
// (401/403/404/anything else) or an empty response. Deliberately
// simple and general -- it does not try to parse or understand the
// body's content, only whether the server's own status line indicates
// success.
func looksAllowed(statusCode int, body []byte) bool {
	return statusCode >= 200 && statusCode < 300 && len(bytes.TrimSpace(body)) > 0
}

// stripPayload removes every occurrence (raw, HTML-escaped, and
// URL-escaped) of payload from body before comparison -- the same
// Phase 3.3 lesson ssrf already applies proactively: an endpoint that
// merely ECHOES its input (section 10's "reflection vs file access")
// must never be mistaken for one that returns genuinely different
// content, just because the two probes' echoed strings differ from
// each other. Applied here from the start, not discovered the hard
// way a third time.
func stripPayload(body []byte, payload string) []byte {
	s := string(body)
	for _, form := range []string{payload, html.EscapeString(payload), url.QueryEscape(payload)} {
		if form == "" {
			continue
		}
		s = strings.ReplaceAll(s, form, "")
	}
	return []byte(s)
}

// containsMarker reports whether body contains marker verbatim --
// section 9's "strong evidence: protected synthetic marker appears in
// response." An empty marker never matches anything (guards against a
// misconfigured empty TraversalCase.Marker being trivially "found" in
// every response).
func containsMarker(body []byte, marker string) bool {
	return marker != "" && bytes.Contains(body, []byte(marker))
}
