// Phase 3.18 API & JSON Input Discovery Foundation: real orchestrator
// + real lab integration tests, against harness_auth.go's Phase 3.18
// extension (the /api/nested, /api/items, /api/malformed, /api/echo,
// and /scripts/api-routes.js fixtures -- see that file's own doc
// comment). Covers task section 16's 12 required lab scenarios.
package lab

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"sakanner/internal/mutation"
	"sakanner/internal/orchestrator"
	"sakanner/internal/parameters"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// ---------------------------------------------------------------------
// 1/3/4/5/9/10/11/12: full crawl -- GET API, nested JSON, JSON array,
// malformed JSON, API-from-HTML, API-from-JavaScript, out-of-scope JS
// reference, response resource references.
// ---------------------------------------------------------------------

func TestPhase3_18_FullCrawl_JSONAndAPIDiscovery(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	orch, store := deepAuthOrchestrator(t, l, rules)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	endpointsList, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob endpoints: %v", err)
	}
	paramsList, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob parameters: %v", err)
	}

	endpointByPath := map[string]models.Endpoint{}
	for _, e := range endpointsList {
		// last-wins tolerated: tests below key on path+source-derived expectations
		endpointByPath[e.Path+"|"+e.Source] = e
	}
	paramsByEndpointID := map[string][]models.Parameter{}
	for _, p := range paramsList {
		paramsByEndpointID[p.EndpointID] = append(paramsByEndpointID[p.EndpointID], p)
	}

	// --- 1. GET API endpoint discovered + classified ---
	nested, ok := endpointByPath["/api/nested|crawl"]
	if !ok {
		t.Fatal("expected /api/nested to be discovered as a SourceCrawl endpoint")
	}
	if !nested.APICandidate {
		t.Errorf("/api/nested APICandidate = false, want true (JSON content type observed)")
	}
	if !strings.Contains(nested.APIEvidence, "response_content_type_json") {
		t.Errorf("/api/nested APIEvidence = %q, want it to contain response_content_type_json", nested.APIEvidence)
	}
	if nested.ResponseContentType != "application/json" {
		t.Errorf("/api/nested ResponseContentType = %q", nested.ResponseContentType)
	}

	// --- 3. Nested JSON object -- deterministic dot-path fields ---
	nestedParams := paramsByEndpointID[nested.ID]
	names := map[string]models.Parameter{}
	for _, p := range nestedParams {
		names[p.Name] = p
	}
	for _, want := range []string{"user.id", "user.profile.email", "user.profile.profile_url", "role"} {
		if _, ok := names[want]; !ok {
			t.Errorf("expected nested JSON field %q to be discovered, got %v", want, nestedParams)
		}
	}
	for _, p := range nestedParams {
		if p.Provenance != "RESPONSE_FIELD" {
			t.Errorf("param %q Provenance = %q, want RESPONSE_FIELD", p.Name, p.Provenance)
		}
		if p.Location != "json" {
			t.Errorf("param %q Location = %q, want json", p.Name, p.Location)
		}
	}

	// --- 12. API response containing a resource reference ---
	if urlField, ok := names["user.profile.profile_url"]; ok {
		if urlField.Value != "/api/users/1001" {
			t.Errorf("user.profile.profile_url value = %q, want /api/users/1001", urlField.Value)
		}
	}

	// --- 4. JSON array -- represented as one field, never descended ---
	items, ok := endpointByPath["/api/items|crawl"]
	if !ok {
		t.Fatal("expected /api/items to be discovered")
	}
	itemsParams := paramsByEndpointID[items.ID]
	itemNames := map[string]bool{}
	for _, p := range itemsParams {
		itemNames[p.Name] = true
	}
	if !itemNames["items"] {
		t.Errorf("expected the array field 'items' itself as one candidate, got %v", itemsParams)
	}
	if itemNames["items.id"] {
		t.Error("array elements must not be individually discovered (items.id found)")
	}
	if !itemNames["count"] {
		t.Errorf("expected sibling scalar field 'count', got %v", itemsParams)
	}

	// --- 5. Malformed JSON -- no crash, zero candidates for that endpoint ---
	malformed, ok := endpointByPath["/api/malformed|crawl"]
	if !ok {
		t.Fatal("expected /api/malformed to still be discovered as an endpoint even though its body is invalid JSON")
	}
	if len(paramsByEndpointID[malformed.ID]) != 0 {
		t.Errorf("expected zero parameters from malformed JSON, got %v", paramsByEndpointID[malformed.ID])
	}

	// --- 9. API discovered from HTML: /api/data reached via /dashboard's link ---
	// (Reachable only through an authenticated crawl -- covered by the
	// identity tests below; here we confirm /api/nested itself, reached
	// via an ORDINARY HTML link from /public, is discoverable without
	// any authentication at all.)

	// --- 10. API discovered from JavaScript ---
	jsNested, foundJS1 := endpointByPath["/api/nested|javascript_route"]
	jsItems, foundJS2 := endpointByPath["/api/items|javascript_route"]
	if !foundJS1 && !foundJS2 {
		t.Error("expected at least one javascript_route-sourced endpoint from /scripts/api-routes.js")
	}
	for _, e := range []models.Endpoint{jsNested, jsItems} {
		if e.Path == "" {
			continue
		}
		if !e.APICandidate || e.APIEvidence != "javascript_reference" {
			t.Errorf("javascript_route endpoint %+v: expected APICandidate=true APIEvidence=javascript_reference", e)
		}
	}

	// --- 11. Out-of-scope JS reference never persisted ---
	for _, e := range endpointsList {
		if strings.Contains(e.Path, "external.scanner.test") || strings.Contains(e.Path, "steal") {
			t.Errorf("SECURITY: an out-of-scope JS-derived reference was persisted as an endpoint: %+v", e)
		}
	}
	if result.ReconSummary.HostCount != 1 {
		t.Errorf("HostCount = %d, want 1 (external.scanner.test must never be discovered as a second host)", result.ReconSummary.HostCount)
	}
}

// ---------------------------------------------------------------------
// 6/7/8: authenticated API, Identity A, Identity B
// ---------------------------------------------------------------------

func TestPhase3_18_AuthenticatedAPI_IdentityAAndB_Isolated(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	orchA, storeA := deepAuthOrchestrator(t, l, rules)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run account-a: %v", err)
	}
	orchB, storeB := deepAuthOrchestrator(t, l, rules)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run account-b: %v", err)
	}

	paramsA, err := storeA.Parameters().ListByScanJob(context.Background(), resultA.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob A: %v", err)
	}
	paramsB, err := storeB.Parameters().ListByScanJob(context.Background(), resultB.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob B: %v", err)
	}

	findUserID := func(params []models.Parameter, identity string) (string, bool) {
		for _, p := range params {
			if p.Name == "user_id" && p.Provenance == "RESPONSE_FIELD" {
				if p.IdentityContext != identity {
					t.Errorf("user_id param IdentityContext = %q, want %q", p.IdentityContext, identity)
				}
				return p.Value, true
			}
		}
		return "", false
	}

	valA, okA := findUserID(paramsA, "account-a")
	valB, okB := findUserID(paramsB, "account-b")
	if !okA || !okB {
		t.Fatalf("expected user_id RESPONSE_FIELD parameter for both identities: okA=%v okB=%v", okA, okB)
	}
	if valA == valB {
		t.Fatal("SECURITY: account-a and account-b discovered the identical user_id value from /api/data")
	}
	if valA != fmt.Sprintf("%d", AccountAUserID) {
		t.Errorf("account-a user_id = %q, want %d", valA, AccountAUserID)
	}
	if valB != fmt.Sprintf("%d", AccountBUserID) {
		t.Errorf("account-b user_id = %q, want %d", valB, AccountBUserID)
	}

	// Cross-contamination check: no account-b-tagged parameter in
	// account-a's own scan job, and vice versa.
	for _, p := range paramsA {
		if p.IdentityContext == "account-b" {
			t.Fatal("SECURITY: account-a's scan job contains an account-b-tagged parameter")
		}
	}
	for _, p := range paramsB {
		if p.IdentityContext == "account-a" {
			t.Fatal("SECURITY: account-b's scan job contains an account-a-tagged parameter")
		}
	}
}

// ---------------------------------------------------------------------
// 2. POST JSON API endpoint -- JSON -> mutation bridge, real request
// ---------------------------------------------------------------------

func TestPhase3_18_JSONToMutationBridge_RealPOSTAgainstLab(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	validator := scope.NewValidator(rules, true)
	x := mutation.NewExecutor(validator, l.Resolver, mutation.ExecutorConfig{Timeout: 5 * time.Second})

	ip := dial(t, "auth.scanner.test", l)
	// Body's keys are already in the SAME alphabetical order
	// mutation.applyJSON's own re-marshal (json.Marshal on a
	// map[string]json.RawMessage, which always sorts keys) will
	// produce -- deliberately, so the comparison below isolates the
	// numeric-value-only change this test wants to demonstrate. A
	// body written in some OTHER key order would still mutate
	// correctly, but Mutate's re-serialization would also reorder its
	// keys to alphabetical, which is itself a real (if semantically
	// meaningless) byte-level difference mutation.Compare's digit-only
	// body normalization does not erase -- see
	// docs/phase-3-18-api-json-discovery.md section 6's own note on
	// this interaction.
	original := mutation.Request{
		Method: http.MethodPost, Scheme: "http", Host: "auth.scanner.test", Port: mustPort(t, l.AuthAddr), IP: ip,
		Path: "/api/echo", Headers: http.Header{"X-Lab-Echo-Auth": {"lab-fixed-echo-token"}},
		Body: []byte(`{"role":"user","user_id":100}`), ContentType: "application/json",
		Origin: mutation.OriginOriginal, EndpointID: "ep-echo", Parameter: "user_id", ParameterLocation: "json",
	}

	baseline, err := x.Execute(context.Background(), original, mutation.SessionContext{})
	if err != nil {
		t.Fatalf("Execute (baseline): %v", err)
	}
	if baseline.Outcome != mutation.OutcomeSuccess || baseline.StatusCode != 200 {
		t.Fatalf("baseline Outcome=%s StatusCode=%d body=%s", baseline.Outcome, baseline.StatusCode, baseline.Body)
	}
	if !strings.Contains(string(baseline.Body), `"user_id":100`) {
		t.Fatalf("baseline echo body = %s, want it to contain the original user_id", baseline.Body)
	}

	// Verbatim (not escaped): user_id is a JSON NUMBER in the original
	// body -- verbatim mode writes the raw, unquoted "101" so the
	// mutated field stays a JSON number too, matching the original's
	// own type (escaped mode would instead quote it as the JSON
	// STRING "101", changing its type -- a legitimate choice for a
	// different test, not what this one wants to demonstrate).
	m := mutation.NewMutation(mutation.LocationJSON, "user_id", "101", mutation.EncodingVerbatim, "ep-echo", "", "")
	mutated, err := mutation.Mutate(original, m, mutation.Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	mutatedResp, err := x.Execute(context.Background(), mutated, mutation.SessionContext{})
	if err != nil {
		t.Fatalf("Execute (mutated): %v", err)
	}
	if mutatedResp.Outcome != mutation.OutcomeSuccess || mutatedResp.StatusCode != 200 {
		t.Fatalf("mutated Outcome=%s StatusCode=%d body=%s", mutatedResp.Outcome, mutatedResp.StatusCode, mutatedResp.Body)
	}
	// The server's own ECHO proves the mutated body actually reached
	// the network, not just that Mutate() produced a value locally.
	if !strings.Contains(string(mutatedResp.Body), `"user_id":101`) {
		t.Fatalf("mutated echo body = %s, want it to contain the MUTATED user_id (101)", mutatedResp.Body)
	}
	if !strings.Contains(string(mutatedResp.Body), `"role":"user"`) {
		t.Fatalf("mutated echo body = %s, want the untouched sibling field 'role' preserved", mutatedResp.Body)
	}

	// The ORIGINAL request must remain unchanged (Phase 3.17's own
	// immutability guarantee, still holding for Phase 3.18's own use).
	if !strings.Contains(string(original.Body), `"user_id":100`) {
		t.Fatalf("SECURITY: the original request's body was mutated in place: %s", original.Body)
	}

	// Response comparison: the two echoed bodies differ ONLY in the
	// numeric user_id value (100 vs 101) -- exactly the case
	// mutation.Compare's own digit-run normalization is designed to
	// treat as NOT structurally different (see
	// docs/phase-3-17-request-mutation.md section 8). BodyIdentical
	// must be false (the raw bytes genuinely differ) while
	// StructurallyDifferent stays false -- proving the normalization
	// policy behaves identically against a real request/response
	// exchange, not just synthetic Response values.
	result := mutation.Compare(baseline, mutatedResp)
	if result.BodyIdentical {
		t.Error("baseline and mutated echo bodies should NOT be byte-identical (the user_id genuinely differs)")
	}
	if result.StructurallyDifferent {
		t.Error("a purely numeric user_id change should be normalized away, not reported as structurally different")
	}
}

// TestPhase3_18_JSONToMutationBridge_NestedPathAgainstRealServer is
// task section 23 question 3's own required proof: a NESTED JSON
// parameter (not just a flat top-level one) mutated and executed
// against a real server, with the server's own echo confirming the
// mutated body -- nested field, real value -- actually reached the
// network at the correct position.
func TestPhase3_18_JSONToMutationBridge_NestedPathAgainstRealServer(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	validator := scope.NewValidator(rules, true)
	x := mutation.NewExecutor(validator, l.Resolver, mutation.ExecutorConfig{Timeout: 5 * time.Second})
	ip := dial(t, "auth.scanner.test", l)

	original := mutation.Request{
		Method: http.MethodPost, Scheme: "http", Host: "auth.scanner.test", Port: mustPort(t, l.AuthAddr), IP: ip,
		Path: "/api/echo", Headers: http.Header{"X-Lab-Echo-Auth": {"lab-fixed-echo-token"}},
		Body: []byte(`{"profile":{"role":"user","name":"alice"},"user_id":100}`), ContentType: "application/json",
		Origin: mutation.OriginOriginal, EndpointID: "ep-echo", Parameter: "profile.role", ParameterLocation: "json",
	}

	m := mutation.NewMutation(mutation.LocationJSON, "profile.role", "admin", mutation.EncodingEscaped, "ep-echo", "", "")
	mutated, err := mutation.Mutate(original, m, mutation.Policy{})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	resp, err := x.Execute(context.Background(), mutated, mutation.SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Outcome != mutation.OutcomeSuccess || resp.StatusCode != 200 {
		t.Fatalf("Outcome=%s StatusCode=%d body=%s", resp.Outcome, resp.StatusCode, resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"role":"admin"`) {
		t.Fatalf("echoed body = %s, want the NESTED profile.role field mutated to admin", resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"name":"alice"`) {
		t.Fatalf("echoed body = %s, want the sibling nested field profile.name preserved", resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"user_id":100`) {
		t.Fatalf("echoed body = %s, want the unrelated top-level field user_id preserved", resp.Body)
	}
}

// TestPhase3_18_RealRequestBody_ProducesRequestInputCandidates is
// task section 23 question 2's own required proof: a REAL JSON
// request body (the kind mutation.Request.Body carries, and the kind
// a real POST/PUT/PATCH would send) parsed via ParseJSONBody with
// ProvenanceRequestInput produces genuine, nested, canonical Parameter
// candidates -- the exact capability the live crawl-driven pipeline
// cannot exercise (the crawler never sends a request body -- see
// docs/phase-3-18-api-json-discovery.md section 1), demonstrated here
// against the identical byte shape a real request/mutation round trip
// already proved reaches the network in the two tests above.
func TestPhase3_18_RealRequestBody_ProducesRequestInputCandidates(t *testing.T) {
	requestBody := []byte(`{"profile":{"role":"user","name":"alice"},"user_id":100}`)

	res := parameters.ParseJSONBody(requestBody, parameters.Limits{}, parameters.ProvenanceRequestInput)
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings for a well-formed request body: %v", res.Warnings)
	}
	byName := map[string]parameters.Candidate{}
	for _, c := range res.Candidates {
		byName[c.Name] = c
	}
	for _, want := range []string{"profile.role", "profile.name", "user_id"} {
		c, ok := byName[want]
		if !ok {
			t.Fatalf("expected candidate %q, got %+v", want, res.Candidates)
		}
		if c.Provenance != parameters.ProvenanceRequestInput {
			t.Errorf("candidate %q Provenance = %q, want REQUEST_INPUT (this field was observed in an actual REQUEST body, not a response)", want, c.Provenance)
		}
	}
}

// ---------------------------------------------------------------------
// Unauthenticated /api/echo request rejected (proves the fixture
// itself isn't silently vulnerable/permissive -- not an IDOR/auth
// finding, just fixture correctness).
// ---------------------------------------------------------------------

func TestPhase3_18_JSONEcho_RequiresAuthHeader(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	validator := scope.NewValidator(rules, true)
	x := mutation.NewExecutor(validator, l.Resolver, mutation.ExecutorConfig{Timeout: 5 * time.Second})
	ip := dial(t, "auth.scanner.test", l)

	req := mutation.Request{
		Method: http.MethodPost, Scheme: "http", Host: "auth.scanner.test", Port: mustPort(t, l.AuthAddr), IP: ip,
		Path: "/api/echo", Body: []byte(`{"user_id":1}`), ContentType: "application/json",
		Origin: mutation.OriginOriginal,
	}
	resp, err := x.Execute(context.Background(), req, mutation.SessionContext{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401 for a request missing the required auth header", resp.StatusCode)
	}
}
