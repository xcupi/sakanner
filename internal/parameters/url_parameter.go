package parameters

import "strings"

// urlParameterFieldNames is an exact-match, case-insensitive list of
// common URL/destination-reference parameter names -- deliberately a
// superset of internal/detectors/ssrf's own private urlLikeParameterNames
// list (url, uri, target, destination, redirect, callback, webhook,
// endpoint, image, resource), plus a few equally common siblings. Kept
// here, not in that package, so a future active detector never needs
// to duplicate or import it -- mirroring IsLikelySecurityToken/
// IsLikelyObjectIdentifier's own established precedent exactly.
var urlParameterFieldNames = map[string]bool{
	"url": true, "uri": true, "link": true, "target": true,
	"destination": true, "dest": true, "redirect": true, "redirect_uri": true,
	"callback": true, "webhook": true, "endpoint": true, "image": true,
	"resource": true, "next": true, "return_url": true, "returnurl": true,
	"feed": true, "src": true, "href": true, "avatar": true,
}

// IsLikelyURLParameter conservatively reports whether name looks like
// a parameter that carries a URL/destination value -- name-based only,
// never derived from a field's discovered VALUE (a value merely
// shaped like a URL is not, by itself, evidence this parameter is
// meant to hold one -- see internal/detectors/ssrfactive's own
// architecture doc for why the name-only heuristic is this
// foundation's deliberate, conservative starting point). Used by
// internal/detectors/ssrfactive.Eligible and
// internal/detectors/openredirectactive.Eligible.
//
// Also tries a trailing "_value"/"_id" suffix stripped from the
// lowercased name against the same exact-match allowlist (never the
// camelCase check below, which only ever applies to the ORIGINAL,
// un-stripped name) -- internal/parameters.InferPathInputs (Phase
// 3.23) always derives a PATH-location parameter's name this way
// (e.g. "redirect_value", never bare "redirect"), a gap first
// discovered and fixed for IsLikelyCommandParameter (Phase 3.26) and
// IsLikelyFilePathParameter (Phase 3.27) but left unfixed here at the
// time (documented as a known, non-regressed limitation in
// docs/phase-3-26-acceptance-test.md). Fixed now (Phase 3.28) because
// openredirectactive's own path-location support genuinely depends on
// it -- not a retroactive change to ssrfactive's own test suite,
// which is unmodified, and not a widening of any other case this
// function already matched (the pre-existing exact-match/`_url`/
// `_uri`/camelCase-`Url`/`Uri` checks are all unchanged below).
func IsLikelyURLParameter(name string) bool {
	trimmed := strings.TrimSpace(name)
	n := strings.ToLower(trimmed)
	if n == "" {
		return false
	}
	if urlParameterFieldNames[n] {
		return true
	}
	if strings.HasSuffix(n, "_url") || strings.HasSuffix(n, "_uri") ||
		strings.HasSuffix(trimmed, "Url") || strings.HasSuffix(trimmed, "Uri") {
		return true
	}
	for _, suffix := range []string{"_value", "_id"} {
		if base, ok := strings.CutSuffix(n, suffix); ok && urlParameterFieldNames[base] {
			return true
		}
	}
	return false
}
