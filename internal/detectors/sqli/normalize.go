package sqli

import (
	"html"
	"net/url"
	"strings"
)

// normalizeBody strips deterministic-but-varying dynamic content --
// any run of ASCII digits, collapsed to a single "#" -- before
// differential comparison, so ordinary request-to-request variance (a
// footer's request counter, a rendered timestamp, a tracking ID) is
// never mistaken for a behavioral difference the probe itself caused.
//
// This deliberately does NOT attempt to normalize genuinely random
// (non-digit) content -- see docs/phase-3-3-sqli.md "Response
// normalization" for why that's a documented limitation, not an
// oversight: digit-run collapsing is what every dynamic-but-safe
// fixture this detector is verified against actually needs, and
// over-normalizing (e.g. stripping arbitrary substrings) risks erasing
// the very behavioral difference SQL injection detection depends on.
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
// HTML-entity-encoded (the exact form html.EscapeString produces,
// matching every "safe" handler in the Phase 3 lab and the general
// stdlib convention), and URL-percent-encoded -- before differential
// comparison. Without this, ANY endpoint that echoes its parameter
// back verbatim (a reflected-XSS-shaped page, an open redirect's
// auto-generated body, a "not found: X" message) would show a false
// behavioral difference between the true- and false-condition probes
// for the trivial reason that the two payload STRINGS differ, with no
// actual application or SQL logic involved. See
// docs/phase-3-3-sqli.md "Differential detection" for the concrete
// false positives this fixes.
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
