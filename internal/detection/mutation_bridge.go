package detection

import (
	"fmt"
	nethttp "net/http"
	"net/url"
	"sort"

	"sakanner/internal/evidence"
	"sakanner/internal/mutation"
)

// NewMutationRequest builds the canonical ORIGINAL mutation.Request for
// t -- the "obtain canonical request" step of an active detector's
// workflow (docs/phase-3-19-active-detection.md section 2). Every
// provenance field is copied verbatim from t; nothing is inferred or
// guessed. A Target with no Method (an HTTPService-kind target)
// defaults to GET, matching how every existing detector already only
// ever issues GET requests against such a target today.
//
// This function -- and MutationEvidence below -- live in
// internal/detection rather than internal/mutation specifically to
// keep internal/mutation a strictly lower-level, standalone package
// with no dependency on internal/detection: Phase 3.17 originally put
// both functions in internal/mutation itself (accepting a
// detection.Target/returning a detection.RequestResponseEvidence
// directly), which worked fine until Phase 3.19 needed
// internal/detection to import internal/mutation too (for
// Executor.ExecuteMutation) -- an import cycle. Moving the two
// Target/RequestResponseEvidence-aware bridge functions here, and
// leaving internal/mutation with no knowledge of internal/detection at
// all, is the correct fix: internal/mutation was always meant to be
// the lower-level package (see docs/phase-3-17-request-mutation.md's
// own architecture), and this makes that true in the import graph, not
// just in prose. Documented here, not hidden, per this session's own
// established practice of recording a self-caught design correction in
// the open.
func NewMutationRequest(t Target) mutation.Request {
	method := t.Method
	if method == "" {
		method = nethttp.MethodGet
	}
	q := url.Values{}
	if u, err := url.Parse(t.URL); err == nil {
		q = cloneQueryValues(u.Query())
	}

	req := mutation.Request{
		Method:            method,
		Scheme:            t.Scheme,
		Host:              t.Host,
		Port:              t.Port,
		IP:                t.IP,
		Path:              t.Path,
		Query:             q,
		Headers:           nethttp.Header{},
		ScanJobID:         t.ScanJobID,
		HTTPServiceID:     t.HTTPServiceID,
		EndpointID:        t.EndpointID,
		Parameter:         t.Parameter,
		ParameterLocation: t.ParameterLocation,
		IdentityContext:   t.IdentityContext,
		Origin:            mutation.OriginOriginal,
	}

	// Phase 3.21: t.FormFields (nil for every Target this doesn't apply
	// to -- zero behavior change) seeds the baseline request with the
	// form's OTHER already-discovered field values, so a subsequent
	// Mutate call touching exactly one of them produces a request that
	// still looks like a complete, real form submission -- see
	// docs/phase-3-21-form-mutation.md section 3. url.Values.Encode()
	// sorts keys internally (standard library guarantee), so this is
	// deterministic regardless of map iteration order.
	if len(t.FormFields) > 0 {
		switch t.ParameterLocation {
		case "form":
			req.Body = []byte(url.Values(toValues(t.FormFields)).Encode())
			req.ContentType = "application/x-www-form-urlencoded"
		case "query":
			for name, value := range t.FormFields {
				if req.Query.Get(name) == "" {
					req.Query.Set(name, value)
				}
			}
		}
	}
	return req
}

// NewTargetMutation builds the canonical Mutation for t's own
// parameter -- the "construct a controlled Mutation" step every
// active detector uses, mirroring NewMutationRequest's own "construct
// the canonical baseline" role. Centralizes the ONE piece of
// location-specific knowledge every detector would otherwise have to
// duplicate: a path-location parameter needs mutation.NewPathMutation
// (which also needs PathSegmentIndex), every other location uses
// mutation.NewMutation directly -- see
// docs/phase-3-23-path-parameters.md section 3.
func NewTargetMutation(t Target, loc mutation.Location, payload string, encoding mutation.Encoding) mutation.Mutation {
	if loc == mutation.LocationPath {
		return mutation.NewPathMutation(t.Parameter, payload, encoding, t.PathSegmentIndex, t.EndpointID, "", t.IdentityContext)
	}
	return mutation.NewMutation(loc, t.Parameter, payload, encoding, t.EndpointID, "", t.IdentityContext)
}

// toValues turns a plain name->value map into url.Values (one value
// per name) -- FormFields only ever carries the single observed
// value discovery recorded per field name (internal/parameters never
// keeps more than one), so this is a direct, lossless conversion.
func toValues(fields map[string]string) url.Values {
	v := make(url.Values, len(fields))
	for name, value := range fields {
		v[name] = []string{value}
	}
	return v
}

func cloneQueryValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// MutationEvidence builds the exact, existing RequestResponseEvidence
// shape every current detector already populates -- no new evidence
// type, no new storage column (see
// docs/phase-3-17-request-mutation.md sections 9 and 13, and
// docs/phase-3-19-active-detection.md section 4). m is the Mutation
// that produced req, or nil for an ORIGINAL/baseline request. Any
// query parameter value in the rendered request line whose NAME
// matches evidence.IsSensitiveFieldName is replaced with
// evidence.RedactedPlaceholder, and m.Value is redacted the same way
// in the returned Payload field when m.Parameter itself is sensitive --
// the same, single blocklist every other package in this codebase
// already defers to, so a future detector mutating a "password" or
// "token" field never has that value land in a Finding's evidence.
func MutationEvidence(req mutation.Request, resp mutation.Response, m *mutation.Mutation, observation, reason string) RequestResponseEvidence {
	var payload, value string
	if m != nil {
		payload = m.Parameter
		value = m.Value
		if evidence.IsSensitiveFieldName(m.Parameter) {
			value = evidence.RedactedPlaceholder
		}
	} else {
		payload = req.Parameter
	}

	return RequestResponseEvidence{
		Request:          fmt.Sprintf("%s %s", req.Method, redactedMutationRequestLine(req)),
		Response:         fmt.Sprintf("HTTP %d", resp.StatusCode),
		StatusCode:       resp.StatusCode,
		Parameter:        payload,
		Payload:          value,
		ResponseFragment: string(resp.Body),
		Observation:      observation,
		Reason:           reason,
	}
}

// redactedMutationRequestLine renders "SCHEME://HOST/PATH?QUERY" with
// every query parameter value redacted whose NAME is sensitive -- the
// request-LINE only, never the body (a body's mutated field/value is
// already reported separately via Parameter/Payload above, matching
// every existing detector's own RequestResponseEvidence convention of
// never embedding a raw body in the Request field).
func redactedMutationRequestLine(req mutation.Request) string {
	u := req.URL()
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if evidence.IsSensitiveFieldName(k) {
			q[k] = []string{evidence.RedactedPlaceholder}
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
