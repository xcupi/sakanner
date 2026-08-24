package evidence

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// redactedPlaceholder is used everywhere a secret value is replaced --
// task sections 5-10's exact convention ("Authorization: Bearer
// <REDACTED>").
const redactedPlaceholder = "<REDACTED>"

// sensitiveHeaderNames is the exact, centralized blocklist task
// section 5 names -- checked case-insensitively. Redaction removes the
// VALUE only; the header NAME is always preserved so an analyst can
// still see that credentials were present, just not their contents.
var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"api-key":             true,
	"x-access-token":      true,
}

// sensitiveFieldNames is the exact, centralized field-name blocklist
// task section 9 names, applied to JSON/form body keys, query
// parameter names, and generic "key=value"/"key: value" text --
// checked case-insensitively. One list drives every redaction path in
// this file, so a name added here protects headers, URLs, JSON
// bodies, form bodies, and free text uniformly.
var sensitiveFieldNames = map[string]bool{
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"api_key":       true,
	"apikey":        true,
	"authorization": true,
	"client_secret": true,
	"session":       true,
	"private_key":   true,
	// csrf/xsrf variants -- Phase 3.15 finding: an authenticated page's
	// own hidden anti-CSRF form field (e.g. a "settings" form
	// discovered by an authenticated crawl, normalized into a
	// models.Parameter by internal/parameters exactly like any other
	// form field) was NOT covered by this blocklist before, so a
	// discovered parameter literally named "csrf_token"/"xsrf" would
	// have had its observed value persisted/reported unredacted --
	// distinct from Authorization/Cookie, which were already covered
	// at the HEADER level. See
	// docs/phase-3-15-authenticated-crawling.md "Secret handling."
	"csrf":       true,
	"csrf_token": true,
	"xsrf":       true,
	"xsrf_token": true,
}

func isSensitiveFieldName(name string) bool {
	return sensitiveFieldNames[strings.ToLower(strings.TrimSpace(name))]
}

// redactHeaders returns a copy of headers with every sensitive header
// VALUE replaced -- task section 5. nil in, nil out; the input is
// never mutated.
func redactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(k))] {
			out[k] = redactedPlaceholder
			continue
		}
		out[k] = sanitizeControlChars(v)
	}
	return out
}

// sanitizeControlChars neutralizes raw CR/LF and other C0 control
// characters (tab excepted) in a captured header value -- task
// section 36's CRLF-injection case. A target that returns a header
// value containing "\r\nX-Injected: evil" must never have that
// reinterpreted as a second header line by anything that later
// renders or re-emits this stored evidence; nothing is silently
// dropped, each control byte becomes its own visible Go-style escape
// (\r, \n, \xNN) so the original bytes the target actually sent
// remain fully recoverable from the stored text.
func sanitizeControlChars(s string) string {
	if !strings.ContainsAny(s, "\r\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// redactURL parses rawURL and replaces the VALUE of every query
// parameter whose NAME matches sensitiveFieldNames -- task section 8.
// The scheme, host, path, and every non-sensitive parameter are left
// exactly as they were. If rawURL cannot be parsed at all (malformed
// input -- see security_test.go), it is returned unchanged rather than
// panicking or silently dropping data a reader might still need to
// make sense of a malformed finding.
//
// After the structured, per-parameter pass, redactText also runs over
// the whole result -- a parameter's VALUE can itself be a URL carrying
// its own embedded secret-shaped query string (e.g. an SSRF target
// parameter whose value is "http://internal/api?api_key=X"), which a
// top-level-keys-only pass would never see. This second pass is what
// catches that case, at the cost of being a plain, deterministic
// pattern match rather than a full recursive URL parse -- task section
// 7's "do not attempt to identify every possible secret perfectly."
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return redactText(rawURL)
	}
	q := u.Query()
	changed := false
	for key := range q {
		if isSensitiveFieldName(key) {
			q.Set(key, redactedPlaceholder)
			changed = true
		}
	}
	result := rawURL
	if changed {
		// Only rebuild (via Encode(), which re-sorts parameters
		// alphabetically) when something was actually redacted --
		// otherwise the original query string's own parameter order is
		// preserved exactly.
		u.RawQuery = q.Encode()
		result = u.String()
	}
	return redactText(result)
}

// keyValuePattern matches "key=value", "key: value", or JSON-shaped
// "key":"value" / "key": "value" occurrences in free text -- task
// section 7's "use deterministic patterns... do not attempt to
// identify every possible secret perfectly." This single pattern
// drives redactText and the multipart/unknown-content-type fallback in
// redactBody. The separator itself (":" or "=") is captured and
// preserved in the output, so redaction never rewrites "password=x"
// into "password:<REDACTED>" -- only the value changes.
//
// The value class deliberately excludes "/" and ":" on top of the
// obvious quote/whitespace/structural delimiters. Without that
// exclusion, a string containing an EMBEDDED URL (e.g. an SSRF target
// parameter's own value, "http://internal/api?api_key=X") produces a
// false match at "http:" itself -- greedily consuming the ENTIRE rest
// of the string as one bogus "value" and hiding the genuinely
// sensitive "api_key=X" a few characters later, since
// ReplaceAllStringFunc never re-scans inside an already-consumed
// match. Excluding "/"/":" makes "http:" fail to match at all (nothing
// valid follows the ":" before the next "/"), so the scan continues
// past the URL's own scheme/host and finds "api_key=X" as its own,
// correctly-bounded match. The trade-off (documented, not incidental):
// a secret value that itself contains "/" or ":" survives THIS
// generic fallback pattern uncaught -- the structured JSON/form
// parsers (redactJSON/redactForm) have no such gap, since they parse
// real field boundaries rather than scanning text.
var keyValuePattern = regexp.MustCompile(`(?i)("?)([a-z_][a-z0-9_]*)("?)\s*([:=])\s*("?)([^"&,\s}/:]+)("?)`)

// redactText applies the generic key=value/key:value pattern to any
// free-text string (Observation, Reason, ResponseFragment, response
// bodies of an unrecognized content type) -- task section 10's
// "if a response contains a secret unrelated to proving the finding,
// redact it." Only the VALUE capture group is ever replaced; the key
// name, separator, and surrounding quoting are preserved so the
// redacted text stays readable.
func redactText(s string) string {
	return keyValuePattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := keyValuePattern.FindStringSubmatch(match)
		if groups == nil {
			return match
		}
		// groups: 1=openQuoteKey 2=key 3=closeQuoteKey 4=separator 5=openQuoteVal 6=value 7=closeQuoteVal
		key := groups[2]
		if !isSensitiveFieldName(key) {
			return match
		}
		return groups[1] + groups[2] + groups[3] + groups[4] + groups[5] + redactedPlaceholder + groups[7]
	})
}
