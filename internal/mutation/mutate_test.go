package mutation

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func baseRequest() Request {
	return Request{
		Method: http.MethodGet, Scheme: "http", Host: "app.test", Path: "/search",
		Query:   url.Values{"q": {"widgets"}, "page": {"1"}},
		Headers: http.Header{}, Origin: OriginOriginal,
	}
}

func TestMutate_Query_Escaped(t *testing.T) {
	m := NewMutation(LocationQuery, "q", "1' OR '1'='1", EncodingEscaped, "ep-1", "", "")
	req, err := Mutate(baseRequest(), m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if req.Query.Get("q") != "1' OR '1'='1" {
		t.Errorf("q = %q", req.Query.Get("q"))
	}
	if req.Query.Get("page") != "1" {
		t.Errorf("unrelated parameter 'page' was disturbed: %q", req.Query.Get("page"))
	}
	if req.Origin != OriginMutated || req.MutationID != m.ID {
		t.Errorf("Origin/MutationID not set correctly: Origin=%s MutationID=%q want %q", req.Origin, req.MutationID, m.ID)
	}
	if !strings.Contains(req.URL().RawQuery, "q=1%27") {
		t.Errorf("escaped mutation must percent-encode the quote, got RawQuery=%q", req.URL().RawQuery)
	}
}

func TestMutate_Query_Verbatim_PreservesRawBytes(t *testing.T) {
	// A traversal-shaped payload that is ALREADY percent-encoded --
	// verbatim mode must not double-encode the '%' itself.
	payload := "..%2f..%2f..%2fetc%2fpasswd"
	m := NewMutation(LocationQuery, "q", payload, EncodingVerbatim, "ep-1", "", "")
	req, err := Mutate(baseRequest(), m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	raw := req.URL().RawQuery
	if !strings.Contains(raw, "q="+payload) {
		t.Errorf("verbatim mutation must place the payload on the wire unescaped, got RawQuery=%q", raw)
	}
	if strings.Contains(raw, "%2525") {
		t.Errorf("verbatim mutation double-encoded the payload: %q", raw)
	}
}

func TestMutate_Query_DuplicateParameterName_CollapsesToSingleValue(t *testing.T) {
	req := baseRequest()
	req.Query["dup"] = []string{"first", "second", "third"}
	m := NewMutation(LocationQuery, "dup", "mutated", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if got := out.Query["dup"]; len(got) != 1 || got[0] != "mutated" {
		t.Errorf("duplicate parameter mutation should deterministically collapse to one value, got %v", got)
	}
}

func TestMutate_Form_Escaped(t *testing.T) {
	req := baseRequest()
	req.Body = []byte("display_name=old&theme=dark")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "display_name", "<script>alert(1)</script>", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if values.Get("display_name") != "<script>alert(1)</script>" {
		t.Errorf("display_name = %q", values.Get("display_name"))
	}
	if values.Get("theme") != "dark" {
		t.Errorf("unrelated form field 'theme' was disturbed: %q", values.Get("theme"))
	}
}

func TestMutate_Form_Verbatim_NoExistingBody(t *testing.T) {
	m := NewMutation(LocationForm, "cmd", "id;whoami", EncodingVerbatim, "", "", "")
	out, err := Mutate(baseRequest(), m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if string(out.Body) != "cmd=id;whoami" {
		t.Errorf("Body = %q", out.Body)
	}
	if out.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("ContentType = %q", out.ContentType)
	}
}

// ---------------------------------------------------------------------
// Phase 3.21 task section 4's own required matrix for LocationForm:
// spaces, plus signs, ampersands, equals signs, percent encoding,
// Unicode, empty values, duplicate parameters, malformed original
// values, special characters. applyForm itself is unchanged (Phase
// 3.17) -- these tests exercise cases the pre-existing suite above
// did not already cover, rather than re-deriving the function.
// ---------------------------------------------------------------------

func TestMutate_Form_ExistingBody_SpacesPlusAmpersandEqualsPercentUnicode(t *testing.T) {
	req := baseRequest()
	// A pre-existing body already containing every tricky character
	// class: a literal space encoded as "+", a literal "+" encoded as
	// "%2B" (so it is NOT misread as a space), an encoded "&" and "=",
	// percent-encoding itself, and UTF-8 text -- proves the EXISTING
	// sibling fields survive url.ParseQuery/Encode's own round trip
	// unchanged when a DIFFERENT field is the one being mutated.
	req.Body = []byte("greeting=hello+world&literal_plus=a%2Bb&has_amp=a%26b&has_equals=a%3Db&pct=100%25&unicode=h%C3%A9llo+%E6%97%A5%E6%9C%AC%E8%AA%9E")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "greeting", "mutated", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if values.Get("greeting") != "mutated" {
		t.Errorf("greeting = %q, want mutated", values.Get("greeting"))
	}
	for name, want := range map[string]string{
		"literal_plus": "a+b",
		"has_amp":      "a&b",
		"has_equals":   "a=b",
		"pct":          "100%",
		"unicode":      "héllo 日本語",
	} {
		if got := values.Get(name); got != want {
			t.Errorf("sibling field %q = %q, want %q (must survive untouched)", name, got, want)
		}
	}
}

func TestMutate_Form_MutatedValueContainsSpacesPlusAmpersandEqualsPercentUnicode(t *testing.T) {
	req := baseRequest()
	req.Body = []byte("q=old")
	req.ContentType = "application/x-www-form-urlencoded"
	payload := "a b+c&d=e%f 日本語"
	m := NewMutation(LocationForm, "q", payload, EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if got := values.Get("q"); got != payload {
		t.Errorf("q = %q, want the payload round-tripped exactly: %q", got, payload)
	}
}

func TestMutate_Form_EmptyExistingValue_Preserved(t *testing.T) {
	req := baseRequest()
	req.Body = []byte("empty_field=&other=value")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "other", "mutated", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if got := values.Get("empty_field"); got != "" {
		t.Errorf("empty_field = %q, want empty string preserved", got)
	}
	if !strings.Contains(string(out.Body), "empty_field=") {
		t.Errorf("empty_field key itself must still be present in the body, got %s", out.Body)
	}
}

func TestMutate_Form_MutatedValueItselfEmpty(t *testing.T) {
	req := baseRequest()
	req.Body = []byte("q=old&other=value")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "q", "", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if got := values.Get("q"); got != "" {
		t.Errorf("q = %q, want empty", got)
	}
	if values.Get("other") != "value" {
		t.Errorf("sibling field 'other' disturbed: %q", values.Get("other"))
	}
}

func TestMutate_Form_DuplicateExistingFieldName_FirstValueWins(t *testing.T) {
	// url.ParseQuery preserves every value for a repeated key as a
	// slice; url.Values.Encode() re-serializes ALL of them (standard
	// library behavior) -- this test pins down that a duplicate
	// SIBLING field's full value set survives Mutate untouched, only
	// the explicitly targeted field is replaced.
	req := baseRequest()
	req.Body = []byte("tag=a&tag=b&q=old")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "q", "mutated", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		t.Fatalf("mutated form body did not parse: %v", err)
	}
	if got := values["tag"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("duplicate sibling field 'tag' = %v, want [a b] preserved", got)
	}
	if values.Get("q") != "mutated" {
		t.Errorf("q = %q, want mutated", values.Get("q"))
	}
}

func TestMutate_Form_MalformedExistingBody_ReturnsError(t *testing.T) {
	// A body containing a raw, unescaped "%" that isn't valid percent
	// encoding (e.g. "%zz") makes url.ParseQuery fail -- applyForm
	// surfaces this as an error rather than silently discarding the
	// existing body (task's "do not crash on malformed input" combined
	// with "do not silently corrupt other fields": failing loudly here
	// is the correct behavior, since silently dropping every sibling
	// field would violate section 3's preservation requirement worse
	// than a clean error would).
	req := baseRequest()
	req.Body = []byte("q=%zz&other=value")
	req.ContentType = "application/x-www-form-urlencoded"
	m := NewMutation(LocationForm, "q", "mutated", EncodingEscaped, "", "", "")
	if _, err := Mutate(req, m, Policy{}); err == nil {
		t.Fatal("expected an error for a malformed existing form body, got nil")
	}
}

func TestMutate_JSON_Escaped_TopLevelField(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"name":"old","age":30}`)
	m := NewMutation(LocationJSON, "name", `injected"value`, EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if !strings.Contains(string(out.Body), `"name":"injected\"value"`) {
		t.Errorf("escaped JSON mutation must safely quote the value, got body=%s", out.Body)
	}
	if !strings.Contains(string(out.Body), `"age":30`) {
		t.Errorf("unrelated JSON field 'age' was disturbed: %s", out.Body)
	}
}

func TestMutate_JSON_Verbatim_RawInjection(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"role":"user"}`)
	m := NewMutation(LocationJSON, "role", `"admin","extra":true`, EncodingVerbatim, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if !strings.Contains(string(out.Body), `"role":"admin","extra":true`) {
		t.Errorf("verbatim JSON mutation must insert the raw bytes unescaped, got body=%s", out.Body)
	}
}

func TestMutate_JSON_Escaped_NestedField(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"user":{"id":1,"profile":{"email":"old@example.com"}},"role":"user"}`)
	m := NewMutation(LocationJSON, "user.profile.email", "new@example.com", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out.Body, &got); err != nil {
		t.Fatalf("mutated body is not valid JSON: %v (body=%s)", err, out.Body)
	}
	user := got["user"].(map[string]interface{})
	profile := user["profile"].(map[string]interface{})
	if profile["email"] != "new@example.com" {
		t.Errorf("nested email = %v", profile["email"])
	}
	if user["id"].(float64) != 1 {
		t.Errorf("sibling field user.id disturbed: %v", user["id"])
	}
	if got["role"] != "user" {
		t.Errorf("sibling top-level field 'role' disturbed: %v", got["role"])
	}
}

func TestMutate_JSON_Verbatim_NestedField_RawInjection(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"user":{"role":"user"}}`)
	m := NewMutation(LocationJSON, "user.role", `"admin","extra":true`, EncodingVerbatim, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if !strings.Contains(string(out.Body), `"role":"admin","extra":true`) {
		t.Errorf("verbatim nested mutation must splice raw bytes at the correct level, got body=%s", out.Body)
	}
}

func TestMutate_JSON_NestedField_CreatesMissingIntermediateObject(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"existing":1}`)
	m := NewMutation(LocationJSON, "newobj.newfield", "value", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out.Body, &got); err != nil {
		t.Fatalf("mutated body is not valid JSON: %v", err)
	}
	newobj, ok := got["newobj"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'newobj' to be created as an object, got %v", got["newobj"])
	}
	if newobj["newfield"] != "value" {
		t.Errorf("newobj.newfield = %v", newobj["newfield"])
	}
}

func TestMutate_JSON_NestedField_ExistingLeafNotObject_Errors(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"user":"not-an-object"}`)
	m := NewMutation(LocationJSON, "user.email", "x@example.com", EncodingEscaped, "", "", "")
	if _, err := Mutate(req, m, Policy{}); err == nil {
		t.Fatal("expected an error descending into a JSON field that is not itself an object")
	}
}

func TestMutate_JSON_NestedField_DeterministicAcrossLevels(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"a":{"z":1,"m":2},"b":1}`)
	m := NewMutation(LocationJSON, "a.n", "3", EncodingEscaped, "", "", "")
	out1, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	out2, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if string(out1.Body) != string(out2.Body) {
		t.Fatalf("nested JSON mutation not deterministic: %q vs %q", out1.Body, out2.Body)
	}
}

func TestMutate_JSON_ExistingBodyNotObject_Errors(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`[1,2,3]`)
	m := NewMutation(LocationJSON, "x", "y", EncodingEscaped, "", "", "")
	if _, err := Mutate(req, m, Policy{}); err == nil {
		t.Fatal("expected an error mutating a JSON array body as if it were an object")
	}
}

func TestMutate_JSON_Deterministic_KeyOrder(t *testing.T) {
	req := baseRequest()
	req.Body = []byte(`{"z":1,"a":2,"m":3}`)
	m := NewMutation(LocationJSON, "n", "4", EncodingEscaped, "", "", "")
	out1, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	out2, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if string(out1.Body) != string(out2.Body) {
		t.Fatalf("JSON mutation body not deterministic: %q vs %q", out1.Body, out2.Body)
	}
}

func TestMutate_Path_ReplacesSegment(t *testing.T) {
	req := baseRequest()
	req.Path = "/users/42/profile"
	m := NewPathMutation("id", "999", EncodingEscaped, 1, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if out.Path != "/users/999/profile" {
		t.Errorf("Path = %q", out.Path)
	}
}

// TestMutate_Path_Escaped_ValueWithSpecialCharacters_URLRoundTrips is
// a regression test for a real, pre-existing defect discovered during
// Phase 3.23 development (docs/phase-3-23-path-parameters.md section
// 3): applyPath's EncodingEscaped branch pre-escapes the value via
// url.PathEscape BEFORE storing it into req.Path -- but Request.URL()
// builds a plain url.URL{Path: r.Path, ...} with no RawPath override,
// so url.URL.String() (via EscapedPath()) escapes r.Path a SECOND
// time, double-encoding every "%" the pre-escape already introduced.
// A value containing a single quote and a space (exactly what
// sqliactive's own real probes use) demonstrably fails to round-trip:
// before the fix, url.QueryUnescape(url.PathEscape(payload)) applied
// to the segment extracted from URL().String() does NOT reproduce the
// original payload. This was never caught earlier because
// TestMutate_Path_ReplacesSegment (above) only ever checked req.Path's
// raw string value, never the actual URL a real HTTP request would
// use -- the first thing in this codebase to build a real request
// from an escaped path mutation is Phase 3.23's own detector
// integration.
func TestMutate_Path_Escaped_ValueWithSpecialCharacters_URLRoundTrips(t *testing.T) {
	req := baseRequest()
	req.Host = "example.test"
	req.Path = "/users/1"
	payload := "1' OR '1'='1"
	m := NewPathMutation("id", payload, EncodingEscaped, 1, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	u := out.URL()
	parsedBack, err := url.Parse(u.String())
	if err != nil {
		t.Fatalf("the final URL is not even parseable: %v (%q)", err, u.String())
	}
	segments := strings.Split(strings.TrimPrefix(parsedBack.Path, "/"), "/")
	if len(segments) != 2 {
		t.Fatalf("got path segments %v, want exactly 2", segments)
	}
	if segments[1] != payload {
		t.Fatalf("path segment did not round-trip through the final URL: got %q, want %q (URL was %q)", segments[1], payload, u.String())
	}
}

// TestMutate_Path_Verbatim_KnownLimitation_StillAutoEscapedByURLString
// documents, explicitly and with a passing test (not a silent gap),
// a real, PRE-EXISTING limitation unrelated to and not worsened by
// the fix above: unlike LocationQuery (RawQueryOverride) and
// LocationForm (a pre-serialized body byte slice), LocationPath has
// no raw-output escape hatch in Request.URL() -- url.URL.String()
// will always auto-escape whatever bytes are placed into Path, so
// EncodingVerbatim cannot achieve genuinely byte-for-byte,
// unescaped-on-the-wire output for a path segment the way it can for
// query/form. Neither sqliactive nor xssactive ever requests
// EncodingVerbatim for any location, so nothing in this codebase
// currently depends on true verbatim path output -- closing this gap
// (e.g. adding a RawPathOverride mirroring RawQueryOverride) is out
// of Phase 3.23's own stated scope. This test exists so the
// limitation is a stated, verified property, not an unexamined
// assumption.
func TestMutate_Path_Verbatim_KnownLimitation_StillAutoEscapedByURLString(t *testing.T) {
	req := baseRequest()
	req.Host = "example.test"
	req.Path = "/users/1"
	// A value that is ALREADY percent-encoded, as EncodingVerbatim's
	// own stated purpose requires (task: "a payload that is already
	// percent-encoded... and must not be double-encoded").
	alreadyEncoded := "%2e%2e"
	m := NewPathMutation("id", alreadyEncoded, EncodingVerbatim, 1, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	u := out.URL()
	if strings.Contains(u.String(), alreadyEncoded) {
		t.Fatal("verbatim path output unexpectedly survived un-re-escaped -- if this now passes, the known limitation documented here has been fixed; update this test and docs/phase-3-23-path-parameters.md accordingly")
	}
}

func TestMutate_Path_IndexOutOfRange_Errors(t *testing.T) {
	req := baseRequest()
	req.Path = "/users/42"
	m := NewPathMutation("id", "999", EncodingEscaped, 5, "", "", "")
	if _, err := Mutate(req, m, Policy{}); err == nil {
		t.Fatal("expected an error for an out-of-range path segment index")
	}
}

func TestMutate_Header_DeniedByDefaultPolicy(t *testing.T) {
	m := NewMutation(LocationHeader, "X-Forwarded-For", "127.0.0.1", EncodingEscaped, "", "", "")
	if _, err := Mutate(baseRequest(), m, Policy{}); err == nil {
		t.Fatal("expected an error mutating a header with no allowlist -- headers must never be mutated by default")
	}
}

func TestMutate_Header_AllowedByPolicy(t *testing.T) {
	m := NewMutation(LocationHeader, "X-Forwarded-For", "127.0.0.1", EncodingEscaped, "", "", "")
	out, err := Mutate(baseRequest(), m, Policy{AllowedHeaders: []string{"x-forwarded-for"}})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if out.Headers.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("header not applied: %v", out.Headers)
	}
}

func TestMutate_Cookie_DeniedByDefaultPolicy(t *testing.T) {
	m := NewMutation(LocationCookie, "role", "admin", EncodingEscaped, "", "", "")
	if _, err := Mutate(baseRequest(), m, Policy{}); err == nil {
		t.Fatal("expected an error mutating a cookie with no allowlist -- cookies must never be mutated by default")
	}
}

func TestMutate_Cookie_AllowedByPolicy_ReplacesExisting(t *testing.T) {
	req := baseRequest()
	req.Cookies = []*http.Cookie{{Name: "role", Value: "user"}, {Name: "sid", Value: "abc"}}
	m := NewMutation(LocationCookie, "role", "admin", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{AllowedCookies: []string{"role"}})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if len(out.Cookies) != 2 {
		t.Fatalf("cookie count changed unexpectedly: %v", out.Cookies)
	}
	for _, c := range out.Cookies {
		if c.Name == "role" && c.Value != "admin" {
			t.Errorf("role cookie not mutated: %v", c)
		}
		if c.Name == "sid" && c.Value != "abc" {
			t.Errorf("unrelated cookie 'sid' disturbed: %v", c)
		}
	}
}

func TestMutate_Cookie_AllowedByPolicy_AddsNew(t *testing.T) {
	m := NewMutation(LocationCookie, "role", "admin", EncodingEscaped, "", "", "")
	out, err := Mutate(baseRequest(), m, Policy{AllowedCookies: []string{"role"}})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if len(out.Cookies) != 1 || out.Cookies[0].Name != "role" || out.Cookies[0].Value != "admin" {
		t.Errorf("cookie not added: %v", out.Cookies)
	}
}

func TestMutate_NeverModifiesOriginal(t *testing.T) {
	original := baseRequest()
	m := NewMutation(LocationQuery, "q", "payload", EncodingEscaped, "", "", "")
	_, err := Mutate(original, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if original.Query.Get("q") != "widgets" {
		t.Errorf("SECURITY: Mutate changed the original request's query: %v", original.Query)
	}
	if original.Origin != OriginOriginal || original.MutationID != "" {
		t.Errorf("SECURITY: Mutate changed the original request's Origin/MutationID: %s %q", original.Origin, original.MutationID)
	}
}

func TestMutate_TwoMutationsFromSameOriginal_Independent(t *testing.T) {
	original := baseRequest()
	mA := NewMutation(LocationQuery, "q", "payload-A", EncodingEscaped, "", "", "")
	mB := NewMutation(LocationQuery, "q", "payload-B", EncodingEscaped, "", "", "")
	reqA, err := Mutate(original, mA, Policy{})
	if err != nil {
		t.Fatalf("Mutate A: %v", err)
	}
	reqB, err := Mutate(original, mB, Policy{})
	if err != nil {
		t.Fatalf("Mutate B: %v", err)
	}
	if reqA.Query.Get("q") != "payload-A" {
		t.Errorf("branch A = %q", reqA.Query.Get("q"))
	}
	if reqB.Query.Get("q") != "payload-B" {
		t.Errorf("branch B = %q", reqB.Query.Get("q"))
	}
	if original.Query.Get("q") != "widgets" {
		t.Errorf("original disturbed by sibling mutations: %q", original.Query.Get("q"))
	}
}

func TestNewMutation_DeterministicID(t *testing.T) {
	m1 := NewMutation(LocationQuery, "q", "payload", EncodingEscaped, "ep-1", "param-1", "account-a")
	m2 := NewMutation(LocationQuery, "q", "payload", EncodingEscaped, "ep-1", "param-1", "account-a")
	if m1.ID != m2.ID {
		t.Fatalf("identical mutation inputs produced different IDs: %q vs %q", m1.ID, m2.ID)
	}
	if m1.ID == "" {
		t.Fatal("mutation ID must not be empty")
	}
}

func TestNewMutation_DifferentValue_DifferentID(t *testing.T) {
	m1 := NewMutation(LocationQuery, "q", "payload-A", EncodingEscaped, "ep-1", "", "")
	m2 := NewMutation(LocationQuery, "q", "payload-B", EncodingEscaped, "ep-1", "", "")
	if m1.ID == m2.ID {
		t.Fatal("mutations with different values must not collide")
	}
}

func TestNewMutation_DifferentLocation_DifferentID(t *testing.T) {
	m1 := NewMutation(LocationQuery, "q", "payload", EncodingEscaped, "", "", "")
	m2 := NewMutation(LocationForm, "q", "payload", EncodingEscaped, "", "", "")
	if m1.ID == m2.ID {
		t.Fatal("mutations with different locations must not collide")
	}
}

func TestMutate_UnknownLocation_Errors(t *testing.T) {
	m := Mutation{Location: "bogus", Parameter: "x", Value: "y"}
	if _, err := Mutate(baseRequest(), m, Policy{}); err == nil {
		t.Fatal("expected an error for an unknown mutation location")
	}
}

func TestMutate_EncodedParameterName_RoundTrips(t *testing.T) {
	req := baseRequest()
	name := "weird name/with?special=chars"
	m := NewMutation(LocationQuery, name, "value", EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if out.Query.Get(name) != "value" {
		t.Errorf("encoded parameter name did not round-trip: %v", out.Query)
	}
	reparsed, err := url.ParseQuery(out.URL().RawQuery)
	if err != nil {
		t.Fatalf("serialized query did not parse: %v", err)
	}
	if reparsed.Get(name) != "value" {
		t.Errorf("serialized+reparsed query lost the encoded name: %v", reparsed)
	}
}

func TestMutate_EncodedParameterValue_RoundTrips(t *testing.T) {
	req := baseRequest()
	value := "a&b=c?d#e"
	m := NewMutation(LocationQuery, "q", value, EncodingEscaped, "", "", "")
	out, err := Mutate(req, m, Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	reparsed, err := url.ParseQuery(out.URL().RawQuery)
	if err != nil {
		t.Fatalf("serialized query did not parse: %v", err)
	}
	if reparsed.Get("q") != value {
		t.Errorf("encoded value did not round-trip: got %q want %q", reparsed.Get("q"), value)
	}
}
