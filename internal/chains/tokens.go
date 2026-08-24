package chains

import (
	"net/url"
	"strconv"
	"strings"

	"sakanner/pkg/models"
)

// minTokenLength is the shortest a candidate identifier-shaped value
// may be before this package will ever treat it as meaningful
// correlation evidence -- guards against a trivial value like "1" or
// "id" coincidentally appearing everywhere and manufacturing a
// relation out of noise.
const minTokenLength = 4

// resourceValue extracts f's own resource-identifying value: the
// query-string value of f.AffectedParameter within f.URL, for ANY
// vulnerability type (generalizing internal/correlation's own
// resourceIdentifier, which is deliberately IDOR-only for its own,
// different purpose -- see
// docs/phase-3-30-correlation-chain-foundation.md section 5). Returns
// ok=false if there is no parameter, no parseable URL, or the value
// is not identifier-shaped (looksLikeIdentifier) -- a bare, generic
// value is never treated as correlation evidence.
func resourceValue(f models.Finding) (value string, ok bool) {
	if f.AffectedParameter == "" {
		return "", false
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return "", false
	}
	v := u.Query().Get(f.AffectedParameter)
	if v == "" || !looksLikeIdentifier(v) {
		return "", false
	}
	return v, true
}

// looksLikeIdentifier mirrors internal/parameters' own established
// "identifier-shaped value" discipline (Phase 3.23's
// allLookLikeIdentifiers: all-numeric, or contains a digit/hyphen/
// underscore) plus a minimum length -- an ordinary short word never
// qualifies, exactly the same "prefer a false negative over a
// fabricated relation" bias Phase 3.23 already established for path-
// parameter inference.
func looksLikeIdentifier(v string) bool {
	if len(v) < minTokenLength {
		return false
	}
	if _, err := strconv.Atoi(v); err == nil {
		return true
	}
	hasDigit := false
	for _, r := range v {
		if r >= '0' && r <= '9' {
			hasDigit = true
			break
		}
	}
	return hasDigit || strings.ContainsAny(v, "-_")
}

// endpointKey returns f's normalized endpoint identity -- Host, Port,
// and AffectedEndpoint (falling back to the URL path) joined
// unambiguously. Two findings share SAME_ENDPOINT iff their
// endpointKey values match exactly.
func endpointKey(f models.Finding) string {
	path := f.AffectedEndpoint
	if path == "" {
		if u, err := url.Parse(f.URL); err == nil {
			path = u.Path
		}
	}
	host := strings.ToLower(strings.TrimSpace(f.Host))
	return host + "\x1f" + strconv.Itoa(f.Port) + "\x1f" + path
}

// displayEndpoint formats f's endpoint for HUMAN-READABLE evidence
// Detail text ("host:port/path") -- endpointKey's own \x1f-joined
// form is for exact-match COMPARISON only and must never be shown to
// an operator (an unprintable separator byte is not useful CLI
// output).
func displayEndpoint(f models.Finding) string {
	path := f.AffectedEndpoint
	if path == "" {
		if u, err := url.Parse(f.URL); err == nil {
			path = u.Path
		}
	}
	host := strings.ToLower(strings.TrimSpace(f.Host))
	return host + ":" + strconv.Itoa(f.Port) + path
}

// evidenceStrings returns the Content of every Evidence item on f, as
// a flat slice -- this package's own only way of looking at evidence
// content, always treated as opaque text (never re-parsed as JSON;
// see docs/phase-3-30-correlation-chain-foundation.md section 3).
func evidenceStrings(f models.Finding) []string {
	out := make([]string, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		if e.Content != "" {
			out = append(out, e.Content)
		}
	}
	return out
}

// maxSharedEvidenceTokenFrequency bounds how many DISTINCT findings
// (across the WHOLE batch being correlated, not just the pair being
// compared) may share a token before it stops counting as
// SHARED_EVIDENCE. Discovered necessary by direct testing against
// real, varied detector evidence (Phase 3.31's own integration
// testing): a token's SHAPE alone (looksLikeSharedEvidenceToken)
// cannot reliably tell a genuine, per-probe-unique marker apart from
// a detector-wide FIXED constant that happens to contain digits --
// e.g. a percent-encoded XSS payload marker ("%22%27%3E%3Cscript...",
// digits from the hex encoding itself) or a JSON \uXXXX HTML-escape
// artifact ("u003e", split out by the tokenizer's own backslash
// delimiter) both satisfy the shape check but appear IDENTICALLY in
// every finding of that type. FREQUENCY is the robust signal instead:
// a genuinely shared, per-probe value appears in only the handful of
// findings it actually relates to; a fixed/boilerplate constant
// appears across most or all findings of its own kind. A small,
// hard-coded threshold (never learned/configurable) keeps this
// deterministic and simple to reason about.
const maxSharedEvidenceTokenFrequency = 4

// tokenFrequency counts, for every looksLikeSharedEvidenceToken-shaped
// token appearing anywhere in views' own evidence, how many DISTINCT
// findings (by ID, counted once each regardless of how many times the
// token repeats within one finding's own evidence) contain it --
// computed ONCE per Correlate call and reused for every pairwise
// SHARED_EVIDENCE check, so this is a single O(total evidence size)
// pass, never quadratic in the number of findings.
func tokenFrequency(views map[string]findingView) map[string]int {
	freq := make(map[string]int)
	for _, v := range views {
		seen := make(map[string]bool)
		for _, content := range evidenceStrings(v.finding) {
			for _, tok := range splitTokens(content) {
				if !looksLikeSharedEvidenceToken(tok) || seen[tok] {
					continue
				}
				seen[tok] = true
				freq[tok]++
			}
		}
	}
	return freq
}

// substringOverlap finds the LONGEST token that is
// looksLikeSharedEvidenceToken-shaped, NOT too common across the
// whole batch (freq), and appears as one of the WHOLE, exact tokens
// produced by tokenizing BOTH a and b -- used for SHARED_EVIDENCE.
// Deliberately an EXACT whole-token match, not "is token from a a
// substring of b's raw text": a raw substring check would let a SHORT
// token that happens to be a PREFIX of a much longer, otherwise-rare
// token slip through as a false match (discovered directly by
// integration testing against real evidence: a short prefix of a
// percent-encoded XSS marker payload matched as a substring of
// several DIFFERENT findings' own longer, individually-rare marker
// variants, even though the short prefix's own whole-token frequency
// was low) -- requiring the SAME literal token to appear as its own
// whole token in both a and b closes that gap, and keeps frequency
// counting and matching consistent with each other. Scans a fixed,
// small set of delimited tokens rather than every possible substring
// (which would be unbounded), keeping this a cheap, deterministic,
// single-pass comparison.
func substringOverlap(a, b string, freq map[string]int) (token string, ok bool) {
	bTokens := make(map[string]bool)
	for _, tok := range splitTokens(b) {
		bTokens[tok] = true
	}
	best := ""
	for _, tok := range splitTokens(a) {
		if !looksLikeSharedEvidenceToken(tok) {
			continue
		}
		if freq[tok] > maxSharedEvidenceTokenFrequency {
			continue
		}
		if bTokens[tok] && len(tok) > len(best) {
			best = tok
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// looksLikeSharedEvidenceToken is DELIBERATELY STRICTER than
// looksLikeIdentifier -- discovered necessary by direct testing
// against real, varied detector evidence (Phase 3.31's own
// architecture review): looksLikeIdentifier alone lets two classes of
// systemic false positive through when scanning raw evidence PROSE
// (as opposed to a single finding's own resource-identifier VALUE,
// which resourceValue/looksLikeIdentifier still handles correctly):
//
//  1. Pure-digit tokens like a shared PORT NUMBER -- every finding in
//     one scan against one target naturally shares the same port, so
//     it appears in literally every evidence "request" field; this is
//     never meaningful cross-finding evidence, only an artifact of
//     testing the same target.
//  2. Pure-letter, no-digit tokens like detector-internal schema
//     field names ("response_fragment", "originally-discovered") or a
//     FIXED, REUSED marker/payload constant a single detector always
//     embeds in every one of its own findings' evidence
//     ("COMMAND_INJECTION_MARKER", a percent-encoded XSS marker
//     payload) -- these indicate "produced by the same detector using
//     the same fixed convention," never a genuine relationship
//     between two DIFFERENT findings.
//
// Requiring the token to contain BOTH a digit and a non-digit
// character excludes both classes while keeping genuine markers
// (e.g. "SAKANNER-MARKER-9f31c2", a per-probe-unique mixed
// alphanumeric token) and dotted values like an internal IP address
// ("192.168.1.1", digits mixed with non-digit separators).
func looksLikeSharedEvidenceToken(v string) bool {
	if len(v) < minTokenLength {
		return false
	}
	// A JSON "\uXXXX" HTML-escape sequence (Go's own default
	// json.Marshal HTML-escapes "<"/">"/"&") gets split by this
	// package's own backslash delimiter into a "uXXXX..." fragment --
	// e.g. ">" becomes the token "u003e" (or "u003eHello" if
	// immediately followed by more text). Discovered directly by
	// integration testing: this is an encoding artifact of how the
	// evidence was SERIALIZED, never genuine per-finding content.
	if strings.HasPrefix(v, "u00") {
		return false
	}
	// A token that's predominantly percent-encoded (>=1 in 4 bytes is
	// a literal "%") is a URL-encoded payload/marker constant a
	// detector embeds identically in every one of its own findings
	// (e.g. a percent-encoded XSS marker payload) -- discovered the
	// same way: a fixed constant, not a genuine per-probe value, even
	// though the hex digits inside satisfy a bare digit/non-digit
	// check.
	if pct := strings.Count(v, "%"); pct > 0 && pct*4 >= len(v) {
		return false
	}
	hasDigit, hasNonDigit := false, false
	for _, r := range v {
		if r >= '0' && r <= '9' {
			hasDigit = true
		} else {
			hasNonDigit = true
		}
	}
	return hasDigit && hasNonDigit
}

// splitTokens breaks s on common delimiters found in URLs/JSON
// evidence content -- a deliberately simple, bounded tokenizer, never
// a full parser.
func splitTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\n', '\t', '\r', '"', '\'', '=', '&', '?', '#', ',', ':', '{', '}', '[', ']', '/', '\\':
			return true
		}
		return false
	})
}
