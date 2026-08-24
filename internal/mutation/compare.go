package mutation

import (
	"bytes"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// volatileHeaders are ignored entirely by comparison -- inherently
// timestamp/request-scoped, carry no structural security signal. See
// docs/phase-3-17-request-mutation.md section 8.
var volatileHeaders = map[string]bool{
	"date":             true,
	"age":              true,
	"expires":          true,
	"etag":             true,
	"x-request-id":     true,
	"x-correlation-id": true,
}

// digitRun is the ONE normalization this package applies to a response
// body before comparing -- deliberately minimal (see the architecture
// doc section 8 for why nothing broader, e.g. UUID/token stripping, is
// applied).
var digitRun = regexp.MustCompile(`[0-9]+`)

// ComparisonResult is a purely descriptive, detector-independent
// comparison of two responses. It never assigns a vulnerability
// meaning to what it finds -- StructurallyDifferent answers "are these
// responses structurally different," never "this is a finding." See
// docs/phase-3-17-request-mutation.md section 8.
type ComparisonResult struct {
	StatusCodeA, StatusCodeB int
	StatusCodeMatch          bool

	ContentTypeA, ContentTypeB string
	ContentTypeMatch           bool

	SizeA, SizeB int64
	SizeDelta    int64
	SizeMatch    bool

	BodyIdentical           bool
	BodyNormalizedIdentical bool

	// HeaderDeltas lists, sorted, the normalized header names whose
	// values differ between a and b (ignoring VolatileHeaders and
	// comparing Set-Cookie by cookie NAME set only, not value).
	HeaderDeltas []string

	// StructurallyDifferent is the one coarse verdict this package
	// produces: true if status code, content type, or normalized body
	// differ. A future detector interprets this according to whatever
	// it is specifically testing for -- this package has no opinion.
	StructurallyDifferent bool
}

// Compare produces a deterministic, side-effect-free comparison of a
// and b. Calling Compare twice with the same two Responses always
// produces an identical ComparisonResult.
func Compare(a, b Response) ComparisonResult {
	r := ComparisonResult{
		StatusCodeA: a.StatusCode, StatusCodeB: b.StatusCode,
		StatusCodeMatch: a.StatusCode == b.StatusCode,

		ContentTypeA: a.ContentType, ContentTypeB: b.ContentType,
		ContentTypeMatch: normalizeContentType(a.ContentType) == normalizeContentType(b.ContentType),

		SizeA: a.BodySize, SizeB: b.BodySize,
		SizeDelta: a.BodySize - b.BodySize,
		SizeMatch: a.BodySize == b.BodySize,

		BodyIdentical: bytes.Equal(a.Body, b.Body),

		HeaderDeltas: headerDeltas(a.Headers, b.Headers),
	}
	r.BodyNormalizedIdentical = normalizeBody(a.Body) == normalizeBody(b.Body)
	r.StructurallyDifferent = !r.StatusCodeMatch || !r.ContentTypeMatch || !r.BodyNormalizedIdentical
	return r
}

func normalizeContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

func normalizeBody(body []byte) string {
	return digitRun.ReplaceAllString(string(body), "#")
}

func normalizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		if volatileHeaders[lk] {
			continue
		}
		if lk == "set-cookie" {
			names := cookieNamesFromSetCookie(vs)
			sort.Strings(names)
			out["set-cookie:names"] = strings.Join(names, ",")
			continue
		}
		cp := append([]string(nil), vs...)
		sort.Strings(cp)
		out[lk] = strings.Join(cp, ",")
	}
	return out
}

func cookieNamesFromSetCookie(raw []string) []string {
	names := make([]string, 0, len(raw))
	for _, v := range raw {
		if i := strings.IndexByte(v, '='); i > 0 {
			names = append(names, strings.TrimSpace(v[:i]))
		}
	}
	return names
}

func headerDeltas(a, b http.Header) []string {
	na, nb := normalizeHeaders(a), normalizeHeaders(b)
	keys := make(map[string]bool, len(na)+len(nb))
	for k := range na {
		keys[k] = true
	}
	for k := range nb {
		keys[k] = true
	}
	var deltas []string
	for k := range keys {
		if na[k] != nb[k] {
			deltas = append(deltas, k)
		}
	}
	sort.Strings(deltas)
	return deltas
}
