package detection

import (
	"encoding/json"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"testing"

	"sakanner/internal/evidence"
	"sakanner/internal/mutation"
)

// These tests were originally TestNewRequestFromTarget_*/TestToEvidence_*
// in internal/mutation, moved here in Phase 3.19 to resolve an import
// cycle -- see mutation_bridge.go's own doc comment.

func TestNewMutationRequest_CopiesProvenance(t *testing.T) {
	tgt := Target{
		Kind: TargetKindEndpoint, ScanJobID: "job-1", HTTPServiceID: "svc-1", EndpointID: "ep-1",
		Host: "app.test", IP: net.ParseIP("10.0.0.5"), Port: 8080, Scheme: "https",
		URL: "https://app.test:8080/search?q=widgets", Path: "/search",
		Method: nethttp.MethodGet, Parameter: "q", ParameterLocation: "query",
		IdentityContext: "account-a",
	}
	req := NewMutationRequest(tgt)

	if req.ScanJobID != "job-1" || req.HTTPServiceID != "svc-1" || req.EndpointID != "ep-1" {
		t.Errorf("provenance not copied: %+v", req)
	}
	if req.Host != "app.test" || req.Port != 8080 || req.Scheme != "https" {
		t.Errorf("dial target not copied: %+v", req)
	}
	if !req.IP.Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("IP not copied: %v", req.IP)
	}
	if req.Parameter != "q" || req.ParameterLocation != "query" {
		t.Errorf("parameter provenance not copied: %+v", req)
	}
	if req.IdentityContext != "account-a" {
		t.Errorf("IdentityContext not copied: %q", req.IdentityContext)
	}
	if req.Query.Get("q") != "widgets" {
		t.Errorf("query not decoded from Target.URL: %v", req.Query)
	}
	if req.Origin != mutation.OriginOriginal || req.MutationID != "" {
		t.Errorf("a Target-derived Request must be ORIGINAL with no MutationID, got Origin=%s MutationID=%q", req.Origin, req.MutationID)
	}
}

// ---------------------------------------------------------------------
// Phase 3.21: FormFields seeding
// ---------------------------------------------------------------------

func TestNewMutationRequest_FormLocation_SeedsBodyFromFormFields(t *testing.T) {
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodPost,
		URL: "http://app.test/login", Path: "/login",
		Parameter: "username", ParameterLocation: "form",
		FormFields: map[string]string{"username": "alice", "password": "hunter2", "csrf_token": "<REDACTED>"},
	}
	req := NewMutationRequest(tgt)
	if req.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("ContentType = %q, want application/x-www-form-urlencoded", req.ContentType)
	}
	values, err := url.ParseQuery(string(req.Body))
	if err != nil {
		t.Fatalf("parse seeded body: %v", err)
	}
	for name, want := range map[string]string{"username": "alice", "password": "hunter2", "csrf_token": "<REDACTED>"} {
		if got := values.Get(name); got != want {
			t.Errorf("body field %q = %q, want %q", name, got, want)
		}
	}
}

func TestNewMutationRequest_QueryLocation_FormSourced_MergesFormFieldsIntoQuery(t *testing.T) {
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodGet,
		URL: "http://app.test/search", Path: "/search",
		Parameter: "q", ParameterLocation: "query",
		FormFields: map[string]string{"q": "widgets", "category": "books"},
	}
	req := NewMutationRequest(tgt)
	if req.Query.Get("q") != "widgets" || req.Query.Get("category") != "books" {
		t.Errorf("FormFields not merged into Query: %v", req.Query)
	}
}

func TestNewMutationRequest_QueryLocation_URLValueTakesPrecedenceOverFormFields(t *testing.T) {
	// The URL is the single source of truth for a query-location
	// Target's OWN observed value (unchanged, pre-Phase-3.21 behavior)
	// -- FormFields only fills in a name the URL doesn't already carry.
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodGet,
		URL: "http://app.test/search?q=live-value", Path: "/search",
		Parameter: "q", ParameterLocation: "query",
		FormFields: map[string]string{"q": "stale-discovery-time-value"},
	}
	req := NewMutationRequest(tgt)
	if req.Query.Get("q") != "live-value" {
		t.Errorf("Query.Get(q) = %q, want live-value (URL takes precedence)", req.Query.Get("q"))
	}
}

func TestNewMutationRequest_NoFormFields_BodyStaysEmpty(t *testing.T) {
	// Backward compatibility: a Target with no FormFields (every
	// non-form Target, and every Target built before this phase)
	// produces byte-for-byte the same empty Body as before.
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodPost,
		URL: "http://app.test/api/echo", Path: "/api/echo",
		Parameter: "role", ParameterLocation: "body",
	}
	req := NewMutationRequest(tgt)
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty when FormFields is unset", req.Body)
	}
	if req.ContentType != "" {
		t.Errorf("ContentType = %q, want empty when FormFields is unset", req.ContentType)
	}
}

func TestNewMutationRequest_FormFields_SpecialCharactersRoundTrip(t *testing.T) {
	// Task section 4's own adversarial matrix: spaces, plus signs,
	// ampersands, equals signs, percent encoding, Unicode -- all must
	// survive being encoded into the seeded body and decoded back out
	// unchanged.
	values := map[string]string{
		"spaces":  "hello world",
		"plus":    "a+b",
		"amp":     "a&b",
		"equals":  "a=b",
		"percent": "100%",
		"unicode": "héllo wörld 日本語",
		"empty":   "",
	}
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodPost,
		URL: "http://app.test/form", Path: "/form",
		Parameter: "spaces", ParameterLocation: "form",
		FormFields: values,
	}
	req := NewMutationRequest(tgt)
	parsed, err := url.ParseQuery(string(req.Body))
	if err != nil {
		t.Fatalf("parse seeded body: %v", err)
	}
	for name, want := range values {
		if got := parsed.Get(name); got != want {
			t.Errorf("field %q round-tripped as %q, want %q", name, got, want)
		}
	}
}

// ---------------------------------------------------------------------
// Phase 3.23: path parameters
// ---------------------------------------------------------------------

func TestNewMutationRequest_PathLocation_PathAlreadyCarriesOriginalValue(t *testing.T) {
	// No special-casing is needed in NewMutationRequest for path
	// parameters -- t.Path already carries the endpoint's full,
	// concrete path (with the original segment value already in
	// place); Mutate's own applyPath is what later replaces exactly
	// the indexed segment. This test pins down that claim directly.
	tgt := Target{
		Kind: TargetKindEndpoint, Host: "app.test", Scheme: "http", Method: nethttp.MethodGet,
		URL: "http://app.test/users/123", Path: "/users/123",
		Parameter: "user_id", ParameterLocation: "path", PathSegmentIndex: 1,
	}
	req := NewMutationRequest(tgt)
	if req.Path != "/users/123" {
		t.Errorf("Path = %q, want /users/123 (unchanged from the Target)", req.Path)
	}
}

func TestNewTargetMutation_PathLocation_UsesNewPathMutation(t *testing.T) {
	tgt := Target{
		Kind: TargetKindEndpoint, Parameter: "user_id", ParameterLocation: "path",
		PathSegmentIndex: 1, EndpointID: "ep-1", IdentityContext: "account-a",
	}
	m := NewTargetMutation(tgt, mutation.LocationPath, "payload", mutation.EncodingEscaped)
	if m.Location != mutation.LocationPath {
		t.Errorf("Location = %q, want path", m.Location)
	}
	if m.PathSegmentIndex != 1 {
		t.Errorf("PathSegmentIndex = %d, want 1", m.PathSegmentIndex)
	}
	if m.Parameter != "user_id" || m.Value != "payload" {
		t.Errorf("Parameter/Value = %q/%q, want user_id/payload", m.Parameter, m.Value)
	}
	if m.SourceEndpointID != "ep-1" || m.IdentityContext != "account-a" {
		t.Errorf("provenance not carried through: %+v", m)
	}
}

func TestNewTargetMutation_NonPathLocation_UsesPlainNewMutation(t *testing.T) {
	tgt := Target{Kind: TargetKindEndpoint, Parameter: "q", ParameterLocation: "query", PathSegmentIndex: 99}
	m := NewTargetMutation(tgt, mutation.LocationQuery, "payload", mutation.EncodingEscaped)
	if m.Location != mutation.LocationQuery {
		t.Errorf("Location = %q, want query", m.Location)
	}
	if m.PathSegmentIndex != 0 {
		t.Errorf("PathSegmentIndex = %d, want 0 (query mutations never carry a segment index, regardless of what garbage the Target held)", m.PathSegmentIndex)
	}
}

func TestNewMutationRequest_NoMethod_DefaultsToGET(t *testing.T) {
	tgt := Target{Kind: TargetKindHTTPService, Host: "app.test", Scheme: "http", URL: "http://app.test/"}
	req := NewMutationRequest(tgt)
	if req.Method != nethttp.MethodGet {
		t.Errorf("Method = %q, want GET for an HTTPService-kind target with no Method", req.Method)
	}
}

func TestNewMutationRequest_DeepClone_MutatingQueryNeverAffectsAnotherCall(t *testing.T) {
	tgt := Target{Host: "app.test", Scheme: "http", URL: "http://app.test/x?q=1"}
	reqA := NewMutationRequest(tgt)
	reqA.Query.Set("q", "TAMPERED")
	reqB := NewMutationRequest(tgt)
	if reqB.Query.Get("q") != "1" {
		t.Fatalf("SECURITY: mutating one NewMutationRequest call's Query affected a later, independent call: %q", reqB.Query.Get("q"))
	}
}

func TestMutationEvidence_OriginalRequest_NilMutation_EmptyPayload(t *testing.T) {
	req := mutation.Request{Method: "GET", Scheme: "http", Host: "app.test", Path: "/x", Query: url.Values{}, Parameter: "q", Origin: mutation.OriginOriginal}
	resp := mutation.Response{StatusCode: 200}
	e := MutationEvidence(req, resp, nil, "baseline observation", "establishes normal behavior")
	if e.Payload != "" {
		t.Errorf("Payload = %q, want empty for a nil Mutation (original/baseline request)", e.Payload)
	}
	if e.Parameter != "q" {
		t.Errorf("Parameter = %q, want %q from req.Parameter", e.Parameter, "q")
	}
}

func TestMutationEvidence_MutatedRequest_PayloadPopulated(t *testing.T) {
	req := mutation.Request{Method: "GET", Scheme: "http", Host: "app.test", Path: "/x", Query: url.Values{"q": {"1' OR '1'='1"}}, Origin: mutation.OriginMutated}
	m := mutation.NewMutation(mutation.LocationQuery, "q", "1' OR '1'='1", mutation.EncodingEscaped, "ep-1", "", "")
	resp := mutation.Response{StatusCode: 200}
	e := MutationEvidence(req, resp, &m, "obs", "reason")
	if e.Payload != "1' OR '1'='1" {
		t.Errorf("Payload = %q", e.Payload)
	}
	if e.Parameter != "q" {
		t.Errorf("Parameter = %q", e.Parameter)
	}
}

func TestMutationEvidence_SensitiveParameterName_ValueRedacted(t *testing.T) {
	req := mutation.Request{Method: "POST", Scheme: "http", Host: "app.test", Path: "/login", Query: url.Values{}, Origin: mutation.OriginMutated}
	m := mutation.NewMutation(mutation.LocationForm, "password", "hunter2-super-secret", mutation.EncodingEscaped, "", "", "")
	resp := mutation.Response{StatusCode: 401}
	e := MutationEvidence(req, resp, &m, "obs", "reason")
	if e.Payload != evidence.RedactedPlaceholder {
		t.Errorf("SECURITY: sensitive parameter value not redacted, got Payload=%q", e.Payload)
	}
	if strings.Contains(e.Payload, "hunter2") {
		t.Fatal("SECURITY: secret value leaked into evidence Payload")
	}
}

func TestMutationEvidence_SensitiveQueryValueInRequestLine_Redacted(t *testing.T) {
	req := mutation.Request{
		Method: "GET", Scheme: "http", Host: "app.test", Path: "/x",
		Query: url.Values{"q": {"widgets"}, "api_key": {"sk-live-abc123secret"}}, Origin: mutation.OriginOriginal,
	}
	resp := mutation.Response{StatusCode: 200}
	e := MutationEvidence(req, resp, nil, "obs", "reason")
	if strings.Contains(e.Request, "sk-live-abc123secret") {
		t.Fatalf("SECURITY: sensitive query parameter value leaked into evidence Request line: %q", e.Request)
	}
	u, err := url.Parse(e.Request[len("GET "):])
	if err != nil {
		t.Fatalf("request line did not parse as a URL: %v (%q)", err, e.Request)
	}
	if got := u.Query().Get("api_key"); got != evidence.RedactedPlaceholder {
		t.Errorf("expected redacted placeholder for api_key, got %q", got)
	}
	if !strings.Contains(e.Request, "q=widgets") {
		t.Errorf("non-sensitive query parameter should remain visible: %q", e.Request)
	}
}

func TestMutationEvidence_ProducesValidJSONWhenMarshaled(t *testing.T) {
	req := mutation.Request{Method: "GET", Scheme: "http", Host: "app.test", Path: "/x", Query: url.Values{}, Origin: mutation.OriginOriginal}
	resp := mutation.Response{StatusCode: 200, Body: []byte("ok")}
	rre := MutationEvidence(req, resp, nil, "obs", "reason")
	ev := NewRequestResponseEvidence("ev-1", "finding-1", rre)
	var roundTrip map[string]interface{}
	if err := json.Unmarshal([]byte(ev.Content), &roundTrip); err != nil {
		t.Fatalf("evidence content is not valid JSON: %v (content=%s)", err, ev.Content)
	}
}
