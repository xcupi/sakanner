package parameters

import (
	"net/url"
	"sort"
	"strings"
)

// PathEndpoint is one observed endpoint's identity, as InferPathInputs
// needs it -- the same (path, method, source) triple Candidate uses,
// kept as its own type here since path inference operates over the
// full set of an entire crawl's endpoints at once (unlike query/form
// discovery, which is naturally per-page).
type PathEndpoint struct {
	Path   string // as internal/endpoints.PathOf would produce it (may include a query string)
	Method string
	Source string
}

// InferPathInputs looks for RELIABLE evidence that a URL path's LAST
// segment is a variable identifier rather than a fixed resource name --
// task's explicit "do NOT assume every path segment is an input...
// only create path inputs when there is reliable evidence a segment is
// variable." The evidence required: at least 2 endpoints, of the same
// method, whose paths are identical in every segment except the last,
// where the last segment differs.
//
// Deliberately conservative: only the LAST segment is ever considered
// variable (the overwhelmingly common REST convention,
// /resource/{id}), never an arbitrary middle segment -- detecting
// middle-segment variability requires reasoning about combinations of
// positions that risks inferring structure that cannot be reliably
// reconstructed (task's "do not invent semantics that cannot be
// reconstructed"). This is a deliberate, documented scope boundary,
// not an oversight -- see docs/phase-3-13-parameter-discovery.md "Path
// input inference: why only the last segment."
//
// A group whose ONLY distinct values are all version-shaped ("v1",
// "v2", ...) never produces a candidate -- Phase 3.23's own finding
// (docs/phase-3-23-path-parameters.md section 2.2): the evidence rule
// applied naively would otherwise misclassify an API version segment
// (a structural routing artifact, not application data) as a
// fuzzable identifier.
//
// limits bounds this function's own work and output exactly like
// Normalize/NormalizeJSONResponses do: a PathEndpoint whose path has
// more than limits.MaxPathSegments segments is skipped before
// grouping, and the resulting candidates are routed through the same
// candidateAggregator discipline (MaxInputsPerEndpoint/MaxTotalInputs)
// those two functions already use.
//
// Deterministic: the same set of endpoints (in any order) always
// produces the same result, sorted by (EndpointPath, EndpointMethod).
func InferPathInputs(eps []PathEndpoint, limits Limits) Result {
	limits = limits.normalized()
	type parsed struct {
		ep       PathEndpoint
		segments []string
	}

	byPrefix := map[string][]parsed{} // key: method + "\x00" + all segments except the last, joined

	for _, ep := range eps {
		segs := pathSegments(ep.Path)
		if len(segs) == 0 {
			continue // root path "/" has no segment to vary
		}
		if len(segs) > limits.MaxPathSegments {
			continue // pathologically deep path -- never considered
		}
		prefix := ep.Method + "\x00" + strings.Join(segs[:len(segs)-1], "/")
		byPrefix[prefix] = append(byPrefix[prefix], parsed{ep: ep, segments: segs})
	}

	prefixes := make([]string, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	agg := newCandidateAggregator()
	for _, prefix := range prefixes {
		group := byPrefix[prefix]
		last := len(group[0].segments) - 1

		distinct := map[string]bool{}
		for _, g := range group {
			distinct[g.segments[last]] = true
		}
		if len(distinct) < 2 {
			continue // every observation agrees -- no evidence this segment varies
		}
		if allVersionShaped(distinct) {
			continue // a routing artifact (v1/v2/...), not application data
		}
		if !allLookLikeIdentifiers(distinct) {
			// A real, self-caught defect (docs/phase-3-23-path-parameters.md
			// section 1.5): "last segment differs" alone cannot tell a
			// genuinely templated resource (/api/{id}) apart from
			// several DIFFERENT, statically-named sibling endpoints
			// that merely share a common parent prefix (e.g.
			// /api/nested, /api/items, /api/malformed -- three real,
			// unrelated endpoints, not instances of one resource).
			// Every value must look identifier-shaped (all-numeric,
			// already checked elsewhere; or contains a digit, hyphen,
			// or underscore) before this group is trusted -- ordinary
			// lowercase-word static resource names essentially never
			// do, while real-world numeric/UUID/hex/slug identifiers
			// almost always do. A narrower net than "any 2+ distinct
			// values," deliberately: prefer a false negative (missing
			// a legitimately templated resource whose sample values
			// happen to look like bare words) over a false positive
			// (fabricating a parameter, and therefore a mutation
			// target, from unrelated static endpoints).
			continue
		}

		var precedingStatic string
		if last > 0 {
			precedingStatic = group[0].segments[last-1]
		}
		allNumeric := true
		for v := range distinct {
			if !isAllDigits(v) {
				allNumeric = false
				break
			}
		}
		name := pathInputName(precedingStatic, allNumeric)

		for _, g := range group {
			agg.add(Candidate{
				EndpointPath: g.ep.Path, EndpointMethod: g.ep.Method, EndpointSource: g.ep.Source,
				Name: name, Location: LocationPath, Value: g.segments[last], Source: SourcePathInference,
				Provenance: ProvenanceRequestInput, PathSegmentIndex: last,
			})
		}
	}

	return agg.finalize(limits)
}

// allVersionShaped reports whether every value in distinct matches
// the version-segment shape "v" followed by one or more digits
// (case-insensitive) -- see InferPathInputs' own doc comment.
func allVersionShaped(distinct map[string]bool) bool {
	for v := range distinct {
		if !isVersionShaped(v) {
			return false
		}
	}
	return true
}

func isVersionShaped(s string) bool {
	if len(s) < 2 || (s[0] != 'v' && s[0] != 'V') {
		return false
	}
	return isAllDigits(s[1:])
}

// allLookLikeIdentifiers reports whether every value in distinct
// looks identifier-shaped -- see InferPathInputs' own doc comment for
// the full rationale.
func allLookLikeIdentifiers(distinct map[string]bool) bool {
	for v := range distinct {
		if !looksLikeIdentifier(v) {
			return false
		}
	}
	return true
}

// looksLikeIdentifier reports whether s is either purely numeric, or
// contains at least one digit, hyphen, or underscore -- the
// conservative shape real-world numeric IDs, UUIDs, hex IDs, and
// hyphen/underscore-separated slugs all share, and ordinary lowercase
// English words (typical static REST resource names: "items",
// "profile", "settings") essentially never do.
func looksLikeIdentifier(s string) bool {
	if isAllDigits(s) {
		return true
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return true
		}
	}
	return false
}

// pathSegments splits a (possibly query-string-carrying) endpoint path
// into its non-empty path segments, ignoring any query string --
// path-shape comparison only ever concerns the path component.
func pathSegments(rawPath string) []string {
	p := rawPath
	if u, err := url.Parse(rawPath); err == nil {
		p = u.Path
	}
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// pathInputName derives a deterministic, conservative name for an
// inferred path input -- a heuristic, documented as such, never a
// guarantee: strips a common trailing "s" from the preceding static
// segment (users -> user, categories is NOT correctly singularized --
// no attempt at real English pluralization is made) and appends "_id"
// when every observed value is purely numeric (the common case), else
// "_value". Falls back to the generic "segment" when there is no
// preceding static segment to base a name on (a single-segment path).
func pathInputName(precedingStatic string, allNumeric bool) string {
	base := "segment"
	if precedingStatic != "" {
		base = strings.TrimSuffix(strings.ToLower(precedingStatic), "s")
		if base == "" {
			base = "segment"
		}
	}
	if allNumeric {
		return base + "_id"
	}
	return base + "_value"
}
