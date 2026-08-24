package mutation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Location names where a mutation applies -- query string, form body,
// JSON body, a path segment, a header, or a cookie. Mirrors
// internal/parameters.Location's own enum values exactly, plus
// "header"/"cookie" which that package's discovery never produces
// today but this package's mutation CAN still explicitly target, under
// Policy's allowlist (see Mutate).
type Location string

const (
	LocationQuery  Location = "query"
	LocationForm   Location = "form"
	LocationJSON   Location = "json"
	LocationPath   Location = "path"
	LocationHeader Location = "header"
	LocationCookie Location = "cookie"
)

// Encoding selects how a mutation's Value reaches the wire. Escaped is
// safe -- it goes through the normal encode path (url.Values.Encode,
// json.Marshal) and can never break the surrounding syntax. Verbatim
// writes Value's bytes onto the wire literally, unescaped -- required
// for a payload that is already percent-encoded/JSON-shaped and must
// not be double-encoded, exactly matching
// internal/detectors/traversal and internal/detectors/cmdinjection's
// own existing, private technique (see
// docs/phase-3-17-request-mutation.md section 4).
type Encoding string

const (
	EncodingEscaped  Encoding = "escaped"
	EncodingVerbatim Encoding = "verbatim"
)

// Mutation describes one controlled change to one input, with enough
// provenance for evidence/logging to explain where it came from
// without ever needing to re-derive it. Two Mutation values built from
// identical inputs always compute the identical ID -- see NewMutation.
type Mutation struct {
	ID        string
	Location  Location
	Parameter string // the parameter/field/header/cookie NAME -- always present, including for path mutations (provenance, even though the mechanical target is PathSegmentIndex)
	Value     string
	Encoding  Encoding
	// PathSegmentIndex is the 0-based path segment Mutate replaces,
	// meaningful only when Location == LocationPath. There is no
	// path-templating concept anywhere upstream to infer which segment
	// a named path parameter corresponds to, so the caller states it
	// explicitly.
	PathSegmentIndex int

	SourceEndpointID  string
	SourceParameterID string
	IdentityContext   string
}

// NewMutation builds a Mutation and computes its deterministic ID.
func NewMutation(loc Location, parameter, value string, encoding Encoding, sourceEndpointID, sourceParameterID, identityContext string) Mutation {
	m := Mutation{
		Location: loc, Parameter: parameter, Value: value, Encoding: encoding,
		SourceEndpointID: sourceEndpointID, SourceParameterID: sourceParameterID, IdentityContext: identityContext,
	}
	m.ID = computeMutationID(m)
	return m
}

// NewPathMutation is NewMutation's path-specific counterpart, since
// path mutations also need PathSegmentIndex.
func NewPathMutation(parameter, value string, encoding Encoding, segmentIndex int, sourceEndpointID, sourceParameterID, identityContext string) Mutation {
	m := NewMutation(LocationPath, parameter, value, encoding, sourceEndpointID, sourceParameterID, identityContext)
	m.PathSegmentIndex = segmentIndex
	m.ID = computeMutationID(m)
	return m
}

// computeMutationID hashes every field that distinguishes one mutation
// from another -- content-derived, never a counter, so the same
// mutation request always gets the same ID regardless of call order,
// goroutine scheduling, or process state (docs/phase-3-17-request-mutation.md
// section 4/12's determinism requirement). Two mutations that differ
// only in Value (e.g. two different payloads targeting the same
// parameter) get different IDs, as intended.
func computeMutationID(m Mutation) string {
	h := sha256.New()
	parts := []string{
		string(m.Location), m.Parameter, string(m.Encoding),
		strconv.Itoa(m.PathSegmentIndex),
		m.SourceEndpointID, m.SourceParameterID, m.Value,
	}
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Policy states which headers/cookies mutation is explicitly permitted
// to target. The zero value permits neither -- task's "do NOT
// automatically mutate arbitrary headers or cookies": a caller must
// opt a specific name in.
type Policy struct {
	AllowedHeaders []string
	AllowedCookies []string
}

func containsFold(list []string, name string) bool {
	for _, v := range list {
		if strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

// Mutate applies m to a clone of original and returns the resulting
// MUTATED Request. original itself is never modified -- Clone runs
// first, unconditionally, before any field is changed (see Request's
// own doc comment on immutability-by-convention). Two calls to Mutate
// against the same original, with different Mutation values, produce
// two independent Requests that share no mutable state -- neither
// observes the other's change.
func Mutate(original Request, m Mutation, policy Policy) (Request, error) {
	req := original.Clone()
	req.Origin = OriginMutated
	req.MutationID = m.ID

	switch m.Location {
	case LocationQuery:
		applyQuery(&req, m)
	case LocationForm:
		if err := applyForm(&req, m); err != nil {
			return Request{}, fmt.Errorf("mutation: form: %w", err)
		}
	case LocationJSON:
		if err := applyJSON(&req, m); err != nil {
			return Request{}, fmt.Errorf("mutation: json: %w", err)
		}
	case LocationPath:
		if err := applyPath(&req, m); err != nil {
			return Request{}, fmt.Errorf("mutation: path: %w", err)
		}
	case LocationHeader:
		if !containsFold(policy.AllowedHeaders, m.Parameter) {
			return Request{}, fmt.Errorf("mutation: header %q is not permitted by policy (task's explicit ban on mutating arbitrary headers)", m.Parameter)
		}
		applyHeader(&req, m)
	case LocationCookie:
		if !containsFold(policy.AllowedCookies, m.Parameter) {
			return Request{}, fmt.Errorf("mutation: cookie %q is not permitted by policy (task's explicit ban on mutating arbitrary cookies)", m.Parameter)
		}
		applyCookie(&req, m)
	default:
		return Request{}, fmt.Errorf("mutation: unknown location %q", m.Location)
	}
	return req, nil
}

func applyQuery(req *Request, m Mutation) {
	q := cloneValues(req.Query)
	if m.Encoding == EncodingVerbatim {
		delete(q, m.Parameter)
		rest := q.Encode()
		raw := m.Parameter + "=" + m.Value
		if rest != "" {
			raw += "&" + rest
		}
		req.RawQueryOverride = &raw
		req.Query = q
		return
	}
	q.Set(m.Parameter, m.Value)
	req.Query = q
	req.RawQueryOverride = nil
}

func applyForm(req *Request, m Mutation) error {
	values := url.Values{}
	if len(req.Body) > 0 {
		parsed, err := url.ParseQuery(string(req.Body))
		if err != nil {
			return fmt.Errorf("parse existing form body: %w", err)
		}
		values = parsed
	}
	if m.Encoding == EncodingVerbatim {
		delete(values, m.Parameter)
		rest := values.Encode()
		raw := m.Parameter + "=" + m.Value
		if rest != "" {
			raw += "&" + rest
		}
		req.Body = []byte(raw)
	} else {
		values.Set(m.Parameter, m.Value)
		req.Body = []byte(values.Encode())
	}
	req.ContentType = "application/x-www-form-urlencoded"
	return nil
}

// applyJSON mutates a field of a JSON object body -- Parameter is
// interpreted as a dot-path (Phase 3.13's own
// internal/parameters.ParseJSONBody convention, e.g. "user.profile.email"),
// so a single-segment name behaves exactly as Phase 3.17's original,
// flat-only implementation did (every one of that phase's own JSON
// tests still passes unchanged against this version), while a dotted
// name now correctly descends into nested structure instead of
// setting a literal key spelled with dots in it. See
// docs/phase-3-18-api-json-discovery.md section 7 for why this fix
// belongs here (a Phase 3.17 gap Phase 3.18's own discovery work
// needs closed) and for the recursive splice technique verbatim mode
// requires at every path level, not just the top.
func applyJSON(req *Request, m Mutation) error {
	segments := strings.Split(m.Parameter, ".")
	if len(segments) == 0 || segments[0] == "" {
		return fmt.Errorf("empty JSON parameter path")
	}

	var out []byte
	var err error
	if m.Encoding == EncodingVerbatim {
		out, err = setJSONPathVerbatim(req.Body, segments, m.Value)
	} else {
		out, err = setJSONPathEscaped(req.Body, segments, m.Value)
	}
	if err != nil {
		return err
	}
	req.Body = out
	req.ContentType = "application/json"
	return nil
}

// unmarshalJSONObject parses body as a JSON object, treating an empty
// body as an empty object (the existing, established convention every
// mutation Location already follows for a not-yet-present body).
func unmarshalJSONObject(body []byte) (map[string]json.RawMessage, error) {
	obj := map[string]json.RawMessage{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &obj); err != nil {
			return nil, fmt.Errorf("existing body is not a JSON object: %w", err)
		}
	}
	return obj, nil
}

// setJSONPathEscaped sets segments[0] (recursing for len(segments)>1,
// creating an empty object for a not-yet-present intermediate key) to
// a safely-encoded value, and marshals the result -- always valid
// JSON at every level, since only already-valid sub-values are ever
// embedded via json.RawMessage, so a single json.Marshal(obj) call at
// each level is safe (unlike the verbatim path below).
func setJSONPathEscaped(body []byte, segments []string, value string) ([]byte, error) {
	obj, err := unmarshalJSONObject(body)
	if err != nil {
		return nil, err
	}
	key := segments[0]
	if len(segments) == 1 {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode json value: %w", err)
		}
		obj[key] = json.RawMessage(encoded)
	} else {
		childBody := []byte("{}")
		if existing, ok := obj[key]; ok {
			childBody = existing
		}
		newChild, err := setJSONPathEscaped(childBody, segments[1:], value)
		if err != nil {
			return nil, fmt.Errorf("descending into %q: %w", key, err)
		}
		obj[key] = json.RawMessage(newChild)
	}
	// json.Marshal on a map[string]T sorts keys alphabetically --
	// deterministic body bytes at every nesting level, with no extra
	// code (standard library guarantee, not this package's own logic).
	return json.Marshal(obj)
}

// setJSONPathVerbatim is setJSONPathEscaped's verbatim counterpart.
// encoding/json validates/compacts every json.RawMessage value it
// marshals as part of a larger structure, so a genuinely malformed or
// structurally-injecting verbatim payload at the LEAF would make
// json.Marshal reject the WHOLE object at every ancestor level that
// tried to embed it via RawMessage -- the exact bug Phase 3.17's own
// top-level verbatim JSON mutation hit and fixed (see
// docs/phase-3-17-acceptance-test.md "Design decisions" #1), now
// generalized: every level from the leaf up to the root splices its
// own key in by string concatenation (mirroring the query/form
// verbatim technique) rather than trusting json.Marshal with a
// RawMessage that might not itself be valid JSON.
func setJSONPathVerbatim(body []byte, segments []string, value string) ([]byte, error) {
	obj, err := unmarshalJSONObject(body)
	if err != nil {
		return nil, err
	}
	key := segments[0]

	var rawChild string
	if len(segments) == 1 {
		rawChild = value // literal, unvalidated bytes -- the whole point of verbatim mode
	} else {
		childBody := []byte("{}")
		if existing, ok := obj[key]; ok {
			childBody = existing
		}
		newChild, err := setJSONPathVerbatim(childBody, segments[1:], value)
		if err != nil {
			return nil, fmt.Errorf("descending into %q: %w", key, err)
		}
		rawChild = string(newChild)
	}

	delete(obj, key)
	rest, err := json.Marshal(obj) // safe: every remaining sibling is already-valid JSON
	if err != nil {
		return nil, fmt.Errorf("marshal remaining json fields: %w", err)
	}
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("encode json key: %w", err)
	}
	injected := string(keyJSON) + ":" + rawChild
	restStr := string(rest)
	if restStr == "{}" {
		return []byte("{" + injected + "}"), nil
	}
	return []byte(restStr[:len(restStr)-1] + "," + injected + "}"), nil
}

// applyPath replaces exactly one path segment with m.Value.
//
// Escaped mode stores m.Value UNMODIFIED -- a real, pre-existing
// defect (discovered during Phase 3.23 development, see
// TestMutate_Path_Escaped_ValueWithSpecialCharacters_URLRoundTrips)
// used to pre-escape it here via url.PathEscape, but Request.URL()
// builds a plain url.URL{Path: r.Path, ...} with no RawPath override
// -- url.URL.String() (via EscapedPath()) ALWAYS escapes Path exactly
// once when serializing, so pre-escaping here caused every "%" the
// pre-escape introduced to be escaped AGAIN, double-encoding the
// value on the wire. Removed: this now mirrors applyQuery's own
// established pattern exactly (that function has never pre-escaped
// either -- it stores the raw value and lets url.Values.Encode()
// perform the one, correct escaping pass later).
//
// Verbatim mode ALSO stores m.Value unmodified, same as before this
// fix -- but note this means true byte-for-byte "verbatim, unescaped
// on the wire" output is NOT actually achievable for LocationPath
// with the current Request.URL() design (unlike LocationQuery/
// LocationForm, which have their own RawQueryOverride/pre-serialized-
// body escape hatches): url.URL.String() will still auto-escape
// whatever raw bytes are placed into Path. This is a real, PRE-
// EXISTING limitation, unrelated to and not worsened by this fix --
// neither sqliactive nor xssactive ever requests EncodingVerbatim for
// any location, so nothing in this codebase currently depends on
// verbatim path output, and closing this second gap is out of Phase
// 3.23's own stated scope (see docs/phase-3-23-path-parameters.md).
func applyPath(req *Request, m Mutation) error {
	trimmed := strings.TrimPrefix(req.Path, "/")
	segments := strings.Split(trimmed, "/")
	if m.PathSegmentIndex < 0 || m.PathSegmentIndex >= len(segments) {
		return fmt.Errorf("path segment index %d out of range (path %q has %d segments)", m.PathSegmentIndex, req.Path, len(segments))
	}
	segments[m.PathSegmentIndex] = m.Value
	req.Path = "/" + strings.Join(segments, "/")
	return nil
}

func applyHeader(req *Request, m Mutation) {
	h := req.Headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set(m.Parameter, m.Value)
	req.Headers = h
}

func applyCookie(req *Request, m Mutation) {
	cookies := cloneCookies(req.Cookies)
	for _, c := range cookies {
		if strings.EqualFold(c.Name, m.Parameter) {
			c.Value = m.Value
			req.Cookies = cookies
			return
		}
	}
	req.Cookies = append(cookies, &http.Cookie{Name: m.Parameter, Value: m.Value})
}
