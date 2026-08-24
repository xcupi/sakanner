// Package endpoints normalizes crawler output into models.Endpoint
// rows. It performs no I/O of its own -- it's a pure transformation over
// already-crawled internal/crawler.Page data, kept separate from the
// crawler itself so a future katana-backed crawl (which produces
// endpoints more directly) can feed the same normalization path.
package endpoints

import (
	"net/url"
	"sort"
	"strings"

	"sakanner/internal/crawler"
	"sakanner/pkg/models"
)

// Source values distinguish where an endpoint was found.
const (
	SourceCrawl      = "crawl"      // the crawled page itself
	SourceLink       = "link"       // an <a href> found on a crawled page
	SourceForm       = "form"       // a <form action> found on a crawled page
	SourceJavaScript = "javascript" // a <script src> found on a crawled page
)

// endpointKey identifies a de-duplication key: the same path+method+
// source combination discovered via multiple pages should only produce
// one Endpoint row.
type endpointKey struct {
	path   string
	method string
	source string
}

// Normalize converts a set of crawled pages into a deduplicated,
// deterministically-ordered slice of Endpoints. Callers fill in
// ID/ScanJobID/HTTPServiceID/CreatedAt before persisting, the same
// pattern internal/fingerprint's Identify uses for Technology.
func Normalize(pages []crawler.Page) []models.Endpoint {
	seen := map[endpointKey]bool{}
	var out []models.Endpoint

	add := func(path, method, source string, candidate bool, evidence []string, responseContentType, actionOrigin string) {
		if path == "" {
			return
		}
		key := endpointKey{path: path, method: method, source: source}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, models.Endpoint{
			Path: path, Method: method, Source: source,
			APICandidate: candidate, APIEvidence: strings.Join(evidence, ","), ResponseContentType: responseContentType,
			ActionOrigin: actionOrigin,
		})
	}

	for _, page := range pages {
		// Only the page's OWN URL (SourceCrawl) has direct response
		// evidence to classify with -- see ClassifyAPI's own doc
		// comment for why SourceLink/SourceForm/SourceJavaScript
		// endpoints get no classification here (they are references
		// found ON a page, not a page this scan itself fetched).
		candidate, evidence := ClassifyAPI(page)
		add(PathOf(page.URL), "GET", SourceCrawl, candidate, evidence, page.ContentType, "")
		for _, link := range page.Links {
			add(PathOf(link), "GET", SourceLink, false, nil, "", "")
		}
		for _, form := range page.Forms {
			// ActionOrigin (Phase 3.21) is computed HERE, from the
			// form's own absolute Action URL, before PathOf (below)
			// discards its host -- see docs/phase-3-21-form-mutation.md
			// section 1 Finding 3 for why this is the one place this
			// information can still be captured.
			add(PathOf(form.Action), form.Method, SourceForm, false, nil, "", originOf(form.Action))
		}
		for _, script := range page.Scripts {
			add(PathOf(script), "GET", SourceJavaScript, false, nil, "", "")
		}
	}

	// Deterministic order (by path, then source) makes output stable for
	// tests and reports, independent of map/slice iteration order
	// upstream.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// PathOf returns just the path (+ query, if any) component of a URL
// string, since Endpoint.Path is a site-relative path, not a full URL.
// A string that isn't a valid absolute URL is returned unchanged (this
// only happens for a form action that was already relative). Exported
// (Phase 3.13) so internal/parameters can compute the exact same
// endpoint identity this package uses, to correlate a discovered input
// back to the Endpoint row it belongs to without duplicating this
// logic.
func PathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Path == "" {
		return "/"
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

// originOf returns raw's normalized "scheme://host:port" origin, or ""
// if raw isn't a parseable absolute URL with a host (e.g. an
// already-relative reference that crawler.resolve could not resolve --
// which only happens for a genuinely malformed action, since a missing/
// empty action already falls back to the page's own absolute URL
// before this function ever sees it). Phase 3.21's own addition, used
// only for form actions (see the SourceForm call site above) -- every
// other Source passes "" explicitly, since only a form's action can
// legitimately point somewhere other than the page that contained it.
//
// Uses net/url's own parsing throughout (Hostname() correctly strips
// userinfo, e.g. "http://good.com@evil.com/" yields "evil.com", not
// "good.com") -- no custom host/port parsing is written here.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + u.Hostname() + ":" + port
}
