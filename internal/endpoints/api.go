package endpoints

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"sakanner/internal/crawler"
)

// SourceJavaScriptRoute distinguishes a URL found INSIDE a script's
// own TEXT (a string literal that looks like an API reference) from
// the pre-existing SourceJavaScript, which means "this URL IS a
// <script src=...> reference" -- an entirely different thing. See
// ExtractAPIRoutes.
const SourceJavaScriptRoute = "javascript_route"

// EvidenceResponseContentTypeJSON and EvidencePathHeuristic are the
// only two reasons ClassifyAPI ever cites -- named constants so a
// caller can compare against them reliably rather than parsing
// APIEvidence's free-text join.
const (
	EvidenceResponseContentTypeJSON = "response_content_type_json"
	EvidencePathHeuristic           = "path_heuristic"
	EvidenceJavaScriptReference     = "javascript_reference"
)

// ClassifyAPI reports whether page looks like an API endpoint, and
// WHY -- evidence-based, never a bare boolean with no explanation
// (docs/phase-3-18-api-json-discovery.md section 4). Only meaningful
// for a page this scan itself fetched (a SourceCrawl endpoint) -- a
// caller has no response evidence for a SourceLink/SourceForm/
// SourceJavaScript endpoint, which is why Normalize (below) only
// calls this for the page's own SourceCrawl row.
//
// Content-Type evidence is checked first and is the strong signal;
// the path heuristic is a weaker, clearly-labeled signal that is
// NEVER the sole basis for silently upgrading confidence -- both may
// fire together, and evidence always names exactly which did.
func ClassifyAPI(page crawler.Page) (candidate bool, evidence []string) {
	if isJSONContentType(page.ContentType) {
		evidence = append(evidence, EvidenceResponseContentTypeJSON)
	}
	if looksLikeAPIPath(PathOf(page.URL)) {
		evidence = append(evidence, EvidencePathHeuristic)
	}
	return len(evidence) > 0, evidence
}

func isJSONContentType(ct string) bool {
	return ct != "" && strings.Contains(strings.ToLower(ct), "json")
}

// numericSegment matches a path segment that is purely numeric (a
// REST-style resource ID, e.g. the "42" in "/users/42").
var numericSegment = regexp.MustCompile(`^[0-9]+$`)

// looksLikeAPIPath is a DELIBERATELY conservative, non-authoritative
// heuristic (task's explicit "do NOT classify something as an API
// merely because its path contains /api/... that may be useful as a
// heuristic signal but must not become authoritative"). It fires on
// exactly two shapes:
//  1. a path segment literally equal to "api" (e.g. "/api/users"),
//  2. a purely-numeric trailing segment following any other segment
//     (e.g. "/users/42") -- a common REST resource+ID shape.
//
// Both are common false-positive-prone shapes on their own (a
// "/api/" directory that serves static HTML; a numeric page number),
// which is exactly why this signal is always reported ALONGSIDE, and
// clearly labeled apart from, any stronger content-type evidence
// rather than trusted alone to assert certainty.
func looksLikeAPIPath(path string) bool {
	u, err := url.Parse(path)
	if err != nil {
		return false
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if strings.EqualFold(seg, "api") {
			return true
		}
		if i > 0 && numericSegment.MatchString(seg) {
			return true
		}
	}
	return false
}

// JSLimits bounds JavaScript route-string extraction -- see
// ExtractAPIRoutes.
type JSLimits struct {
	// MaxRoutesPerScript bounds how many distinct routes ONE script's
	// text may contribute before the rest are discarded.
	MaxRoutesPerScript int
}

// DefaultJSLimits returns safe, positive defaults.
func DefaultJSLimits() JSLimits {
	return JSLimits{MaxRoutesPerScript: 50}
}

func (l JSLimits) normalized() JSLimits {
	if l.MaxRoutesPerScript <= 0 {
		l.MaxRoutesPerScript = DefaultJSLimits().MaxRoutesPerScript
	}
	return l
}

// apiCallShapes are the ONLY call-site prefixes ExtractAPIRoutes
// treats as reliable evidence that a following quoted string is an
// API route reference, not just any quoted string in the file (which
// would produce enormous false-positive noise from CSS class names,
// log messages, and unrelated literals) -- task's explicit "define
// conservative parsing rules."
var apiCallShapes = []string{"fetch", "get", "post", "put", "patch", "delete", "axios"}

// routeLiteral matches one call-shape (from apiCallShapes) followed
// eventually by a quoted string that looks like an absolute http(s)
// URL or an absolute path -- built once from apiCallShapes so the
// list above is the single source of truth for what counts as a
// "reliable" call shape.
var routeLiteral = regexp.MustCompile(
	`(?:` + strings.Join(apiCallShapes, "|") + `)[a-zA-Z0-9_.]*\s*\(\s*['"](https?://[^'"]+|/[^'"]*)['"]`,
)

// ExtractAPIRoutes conservatively extracts API-route-shaped string
// literals from scriptBody -- NOT a JavaScript parser or interpreter
// (task's explicit "do not build a full JavaScript interpreter... do
// not execute arbitrary JavaScript"). It matches a small, fixed set
// of call shapes (fetch/.get/.post/.put/.patch/.delete/axios.*) whose
// first string-literal argument looks like an absolute URL or an
// absolute path -- every other quoted string in the file is ignored.
// Output is deduplicated and sorted (deterministic regardless of
// regex match order), and bounded by limits.MaxRoutesPerScript.
//
// Absolute URLs are returned exactly as written (relative resolution
// only applies to a path-only reference, resolved against base); scope
// enforcement happens at the CALLER, before any of these are ever
// persisted as an Endpoint or dialed -- this function performs no
// network I/O and makes no scope decision itself (task's "scope logic
// itself must remain centralized").
func ExtractAPIRoutes(scriptBody []byte, base *url.URL, limits JSLimits) []string {
	limits = limits.normalized()

	matches := routeLiteral.FindAllSubmatch(scriptBody, -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if len(out) >= limits.MaxRoutesPerScript {
			break
		}
		raw := string(m[1])
		resolved := resolveRouteRef(base, raw)
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, resolved)
	}
	sort.Strings(out)
	return out
}

// resolveRouteRef turns a route reference (already known to be either
// absolute http(s) or path-absolute, per routeLiteral's own match
// shape) into a final string: an absolute URL is returned as-is;
// a path is resolved against base -- the SAME resolution
// internal/crawler already performs for ordinary links, reused here
// via the standard library rather than re-derived.
func resolveRouteRef(base *url.URL, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		return u.String()
	}
	if base == nil {
		return ""
	}
	return base.ResolveReference(u).String()
}
