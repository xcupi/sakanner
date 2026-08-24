package ssrf

import (
	"html"
	"net/url"
	"strings"
)

// normalizeBody strips deterministic-but-varying dynamic content (any
// run of ASCII digits, collapsed to "#") before comparing a probe
// response against baseline -- the same normalization
// internal/detectors/sqli already established, for the identical
// reason: a page's own footer timestamp/request counter must not be
// mistaken for a behavioral difference the probe caused.
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

// stripPayload removes every occurrence of payload from body -- raw,
// HTML-entity-encoded, and URL-percent-encoded -- before comparison.
// Without this, ANY endpoint that echoes its parameter back verbatim
// (the callback URL itself, reflected) would show a false behavioral
// difference between baseline and probe for the trivial reason that
// the two parameter VALUES are different strings, with no server-side
// fetch involved at all. This is the exact false-positive class
// internal/detectors/sqli found and fixed during Phase 3.3 (see
// docs/phase-3-3-sqli.md "Differential detection") -- applied here
// from the start rather than being rediscovered the same way.
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

// fetchErrorPhrases are generic, cross-application phrases suggesting a
// server actually ATTEMPTED an outbound network fetch and it failed --
// evidence of URL-fetching *behavior*, distinct from (and weaker than)
// a confirmed callback. Deliberately generic wording, not tied to any
// one HTTP client library, since this detector cannot know what the
// target application is implemented in.
var fetchErrorPhrases = []string{
	"connection refused",
	"could not connect",
	"could not resolve",
	"network error",
	"fetch failed",
	"dial tcp",
	"no route to host",
	"connection timed out",
}

// containsFetchErrorPhrase reports whether body contains any recognized
// fetch-attempt-failure phrase, case-insensitively.
func containsFetchErrorPhrase(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, p := range fetchErrorPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
