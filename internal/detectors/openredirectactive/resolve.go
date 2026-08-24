package openredirectactive

import (
	"net/url"
	"strings"

	"sakanner/internal/mutation"
)

// isRedirectStatus reports whether status is a 3xx redirect.
func isRedirectStatus(status int) bool {
	return status >= 300 && status < 400
}

// resolveLocation parses resp's Location header and resolves it
// against base (the request's own URL) using RFC 3986 relative-
// reference resolution -- the exact same mechanism net/http's own
// redirect-following uses (url.URL.ResolveReference), so absolute,
// protocol-relative, and relative forms are all handled correctly.
// Returns ok=false if there is no Location header or it fails to
// parse -- never a substring/text-based interpretation.
func resolveLocation(base *url.URL, resp mutation.Response) (resolved *url.URL, raw string, ok bool) {
	raw = resp.Headers.Get("Location")
	if raw == "" {
		return nil, "", false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, raw, false
	}
	return base.ResolveReference(ref), raw, true
}

// matchesDestination reports whether resolved is EXACTLY the
// configured destination -- host (case-insensitive) and port must
// match exactly, and path must match exactly. This is a structural
// comparison of the RESOLVED URL, never a substring check against the
// raw Location text -- see docs/phase-3-28-open-redirect-active.md
// section 2 for why that distinction is the whole point of this
// function.
func matchesDestination(resolved *url.URL, destination *url.URL) bool {
	if resolved == nil || destination == nil {
		return false
	}
	if !strings.EqualFold(resolved.Hostname(), destination.Hostname()) {
		return false
	}
	if resolved.Port() != destination.Port() {
		return false
	}
	return resolved.Path == destination.Path
}
