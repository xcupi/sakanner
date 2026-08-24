package mutation

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// Origin distinguishes a canonical ORIGINAL request (built directly
// from a Target, never touched by Mutate) from a MUTATED request
// (always produced by Mutate, always derived from a clone). See this
// package's own doc comment and docs/phase-3-17-request-mutation.md
// section 3.
type Origin string

const (
	OriginOriginal Origin = "ORIGINAL"
	OriginMutated  Origin = "MUTATED"
)

// Request is the canonical HTTP request representation this package's
// clone/mutate/execute operations work with. It is a plain value type
// -- copying a Request copies every field's header value, but Query/
// Headers/Cookies/Body are reference types in Go (maps, slices), so
// Clone (not a bare Go struct copy) is what a caller must use to get
// an independently-mutable copy. See Clone's own doc comment.
type Request struct {
	Method string
	Scheme string
	Host   string // hostname only, never includes a port
	Port   int
	// IP is the pre-resolved, scope-validated address to dial, if
	// already known (internal/detection.NewMutationRequest always sets
	// it from the source Target's own already-validated IP). nil is
	// valid: Execute resolves and scope-validates the host itself in
	// that case, via the exact same safedial.Dialer.ResolveInScope
	// internal/auth already uses for the same purpose (see
	// docs/phase-3-17-request-mutation.md section 7).
	IP   net.IP
	Path string
	// Query is the decoded query parameter set. RawQueryOverride, when
	// non-nil, takes precedence over Query.Encode() when URL() builds
	// the final query string -- see Mutate's "verbatim" encoding.
	Query            url.Values
	RawQueryOverride *string
	Headers          http.Header
	Cookies          []*http.Cookie
	Body             []byte
	ContentType      string

	// Provenance -- copied verbatim from the source Target (or
	// Endpoint/Parameter) this Request was built from, never derived
	// or guessed.
	ScanJobID     string
	HTTPServiceID string
	EndpointID    string
	// Parameter/ParameterLocation mirror internal/detection.Target's
	// own field names and semantics exactly (ParameterLocation is one
	// of "query"/"body"/"header"/"cookie", matching
	// pkg/models.Parameter.Location's existing convention).
	Parameter         string
	ParameterLocation string
	// IdentityContext is the configured identity name (Phase 3.16)
	// whose session, if any, discovered/will execute this request --
	// never a credential, always safe to log. "" means no identity
	// (unauthenticated, or a bare --auth-profile with no identity
	// wrapper).
	IdentityContext string

	// Origin/MutationID -- see Origin's doc comment. Set only by
	// internal/detection.NewMutationRequest (OriginOriginal, MutationID
	// "") and Mutate (OriginMutated, MutationID from the Mutation that
	// produced it).
	Origin     Origin
	MutationID string
}

// URL builds r's final request URL deterministically: RawQuery comes
// from RawQueryOverride when set (a verbatim query mutation), otherwise
// from Query.Encode() -- which Go's standard library already sorts by
// key, so two Requests with the identical logical query parameter set
// always serialize to byte-identical query strings.
func (r Request) URL() *url.URL {
	rawQuery := r.Query.Encode()
	if r.RawQueryOverride != nil {
		rawQuery = *r.RawQueryOverride
	}
	host := r.Host
	if r.Port != 0 {
		host = net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	return &url.URL{Scheme: r.Scheme, Host: host, Path: r.Path, RawQuery: rawQuery}
}

// Clone returns a deep copy of r: mutating the returned Request's
// Query, Headers, Cookies, Body, or RawQueryOverride never affects r,
// and vice versa. This is what every Mutate call starts from --
// task's "a mutation must never silently overwrite the canonical
// original request" and "no mutation may alter the original request
// or another mutation branch," both of which depend on Clone actually
// being deep, not a shallow Go struct copy (which would still share
// the same underlying Query/Headers maps and Body backing array).
func (r Request) Clone() Request {
	c := r
	c.Query = cloneValues(r.Query)
	c.Headers = r.Headers.Clone()
	if c.Headers == nil {
		c.Headers = http.Header{}
	}
	c.Cookies = cloneCookies(r.Cookies)
	if r.Body != nil {
		c.Body = append([]byte(nil), r.Body...)
	}
	if r.RawQueryOverride != nil {
		v := *r.RawQueryOverride
		c.RawQueryOverride = &v
	}
	if r.IP != nil {
		c.IP = append(net.IP(nil), r.IP...)
	}
	return c
}

func cloneValues(v url.Values) url.Values {
	if v == nil {
		return url.Values{}
	}
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func cloneCookies(cookies []*http.Cookie) []*http.Cookie {
	if cookies == nil {
		return nil
	}
	out := make([]*http.Cookie, len(cookies))
	for i, c := range cookies {
		cp := *c
		out[i] = &cp
	}
	return out
}
