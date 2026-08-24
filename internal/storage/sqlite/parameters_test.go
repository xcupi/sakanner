package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

func seedForParameterTest(t *testing.T, s storage.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if err := s.Assets().Create(ctx, models.Asset{ID: "a1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := s.Hosts().Create(ctx, models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := s.Services().Create(ctx, models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := s.HTTPServices().Create(ctx, models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	if err := s.Endpoints().Create(ctx, models.Endpoint{ID: "e1", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/search", Method: "GET", Source: "crawl", CreatedAt: now}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
}

func TestParameterCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	required := true
	params := []models.Parameter{
		{ID: "p1", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", Classification: "PARAMETER", Method: "GET", Value: "test", Source: "url_query", CreatedAt: now},
		{ID: "p2", ScanJobID: "job1", EndpointID: "e1", Name: "page", Location: "query", Classification: "PARAMETER", Method: "GET", Value: "2", Source: "url_query", Required: &required, CreatedAt: now},
	}
	for _, p := range params {
		if err := s.Parameters().Create(ctx, p); err != nil {
			t.Fatalf("create parameter %s: %v", p.ID, err)
		}
	}

	got, err := s.Parameters().Get(ctx, "p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "q" || got.Location != "query" || got.Value != "test" || got.EndpointID != "e1" {
		t.Errorf("Get = %+v, want name=q location=query value=test endpoint=e1", got)
	}
	if got.Required != nil {
		t.Errorf("Required = %v, want nil (not set on p1)", got.Required)
	}

	got2, err := s.Parameters().Get(ctx, "p2")
	if err != nil {
		t.Fatalf("Get p2: %v", err)
	}
	if got2.Required == nil || *got2.Required != true {
		t.Errorf("p2.Required = %v, want pointer to true", got2.Required)
	}

	list, err := s.Parameters().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListByScanJob returned %d parameters, want 2", len(list))
	}

	if err := s.Parameters().Delete(ctx, "p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Parameters().Get(ctx, "p1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

// TestEndpointAndParameter_IdentityContext_RoundTrips is Phase 3.16's
// storage-level proof that IdentityContext survives a real
// Create/Get/List round trip through SQLite -- not merely held in an
// in-memory struct.
func TestEndpointAndParameter_IdentityContext_RoundTrips(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	// The seeded endpoint (e1) carries no identity context (an
	// unauthenticated crawl) -- a second endpoint, e2, simulates one
	// discovered under "account-a".
	if err := s.Endpoints().Create(ctx, models.Endpoint{
		ID: "e2", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/account", Method: "GET",
		Source: "crawl", IdentityContext: "account-a", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint e2: %v", err)
	}
	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p3", ScanJobID: "job1", EndpointID: "e2", Name: "csrf_token", Location: "form",
		Classification: "FORM_FIELD", Method: "POST", Source: "html_form", IdentityContext: "account-a", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create parameter p3: %v", err)
	}

	gotE1, err := s.Endpoints().Get(ctx, "e1")
	if err != nil {
		t.Fatalf("Get e1: %v", err)
	}
	if gotE1.IdentityContext != "" {
		t.Errorf("e1.IdentityContext = %q, want empty (unauthenticated)", gotE1.IdentityContext)
	}

	gotE2, err := s.Endpoints().Get(ctx, "e2")
	if err != nil {
		t.Fatalf("Get e2: %v", err)
	}
	if gotE2.IdentityContext != "account-a" {
		t.Errorf("e2.IdentityContext = %q, want account-a", gotE2.IdentityContext)
	}

	gotP3, err := s.Parameters().Get(ctx, "p3")
	if err != nil {
		t.Fatalf("Get p3: %v", err)
	}
	if gotP3.IdentityContext != "account-a" {
		t.Errorf("p3.IdentityContext = %q, want account-a", gotP3.IdentityContext)
	}

	endpoints, err := s.Endpoints().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob endpoints: %v", err)
	}
	byID := map[string]models.Endpoint{}
	for _, e := range endpoints {
		byID[e.ID] = e
	}
	if byID["e1"].IdentityContext != "" || byID["e2"].IdentityContext != "account-a" {
		t.Errorf("ListByScanJob did not preserve IdentityContext: %+v", byID)
	}
}

// TestParameter_Hidden_RoundTripAndDefault is Phase 3.21's own
// round-trip test for the new hidden column (migration 0012),
// mirroring TestParameter_Provenance_RoundTripAndDefault's structure.
func TestParameter_Hidden_RoundTripAndDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-hidden", ScanJobID: "job1", EndpointID: "e1", Name: "csrf_token", Location: "form",
		Hidden: true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create p-hidden: %v", err)
	}
	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-visible", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now,
		// Hidden intentionally left unset.
	}); err != nil {
		t.Fatalf("create p-visible: %v", err)
	}

	gotHidden, err := s.Parameters().Get(ctx, "p-hidden")
	if err != nil {
		t.Fatalf("Get p-hidden: %v", err)
	}
	if !gotHidden.Hidden {
		t.Error("Hidden = false, want true")
	}

	gotVisible, err := s.Parameters().Get(ctx, "p-visible")
	if err != nil {
		t.Fatalf("Get p-visible: %v", err)
	}
	if gotVisible.Hidden {
		t.Error("Hidden = true, want false (default)")
	}

	list, err := s.Parameters().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byID := map[string]models.Parameter{}
	for _, p := range list {
		byID[p.ID] = p
	}
	if !byID["p-hidden"].Hidden || byID["p-visible"].Hidden {
		t.Errorf("ListByScanJob did not preserve Hidden: %+v", byID)
	}
}

// TestParameter_PathSegmentIndex_RoundTripAndDefault is Phase 3.23's
// own round-trip test for the new path_segment_index column
// (migration 0013), mirroring TestParameter_Hidden_RoundTripAndDefault's
// structure. A non-path Parameter's PathSegmentIndex is forced to -1
// at Create time regardless of what the caller's struct literal
// happened to leave in the field (parameterRepo.Create's own
// defensive normalization).
func TestParameter_PathSegmentIndex_RoundTripAndDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-path", ScanJobID: "job1", EndpointID: "e1", Name: "user_id", Location: "path",
		PathSegmentIndex: 1, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create p-path: %v", err)
	}
	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-query", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now,
		// PathSegmentIndex intentionally left unset (Go zero value 0)
		// -- Create must still force it to -1, not persist 0.
	}); err != nil {
		t.Fatalf("create p-query: %v", err)
	}

	gotPath, err := s.Parameters().Get(ctx, "p-path")
	if err != nil {
		t.Fatalf("Get p-path: %v", err)
	}
	if gotPath.PathSegmentIndex != 1 {
		t.Errorf("PathSegmentIndex = %d, want 1", gotPath.PathSegmentIndex)
	}

	gotQuery, err := s.Parameters().Get(ctx, "p-query")
	if err != nil {
		t.Fatalf("Get p-query: %v", err)
	}
	if gotQuery.PathSegmentIndex != -1 {
		t.Errorf("PathSegmentIndex = %d, want -1 (forced for a non-path Parameter)", gotQuery.PathSegmentIndex)
	}

	list, err := s.Parameters().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byID := map[string]models.Parameter{}
	for _, p := range list {
		byID[p.ID] = p
	}
	if byID["p-path"].PathSegmentIndex != 1 || byID["p-query"].PathSegmentIndex != -1 {
		t.Errorf("ListByScanJob did not preserve PathSegmentIndex: %+v", byID)
	}
}

func TestParameter_DeleteNonexistent_ReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Parameters().Delete(ctx, "bogus"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Delete(bogus) = %v, want ErrNotFound", err)
	}
}

func TestParameter_CascadeDeletesWithEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{ID: "p1", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}
	if err := s.Endpoints().Delete(ctx, "e1"); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	if _, err := s.Parameters().Get(ctx, "p1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after cascade delete via endpoint: err = %v, want ErrNotFound", err)
	}
}

func TestParameter_CascadeDeletesWithScanJob(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{ID: "p1", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}
	if err := s.ScanJobs().Delete(ctx, "job1"); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if _, err := s.Parameters().Get(ctx, "p1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after cascade delete via scan job: err = %v, want ErrNotFound", err)
	}
}

func TestParameter_RequiredNilRoundTrips(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{ID: "p1", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Parameters().Get(ctx, "p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Required != nil {
		t.Errorf("Required = %v, want nil", got.Required)
	}
}

// TestEndpoint_APIFields_RoundTrip is Phase 3.18's own round-trip
// test for the new APICandidate/APIEvidence/ResponseContentType
// columns (migration 0010), mirroring
// TestEndpointAndParameter_IdentityContext_RoundTrips's exact
// structure.
func TestEndpoint_APIFields_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Endpoints().Create(ctx, models.Endpoint{
		ID: "e-api", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/api/data", Method: "GET", Source: "crawl",
		APICandidate: true, APIEvidence: "response_content_type_json", ResponseContentType: "application/json",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	got, err := s.Endpoints().Get(ctx, "e-api")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.APICandidate {
		t.Error("APICandidate = false, want true")
	}
	if got.APIEvidence != "response_content_type_json" {
		t.Errorf("APIEvidence = %q", got.APIEvidence)
	}
	if got.ResponseContentType != "application/json" {
		t.Errorf("ResponseContentType = %q", got.ResponseContentType)
	}

	// The pre-existing seeded endpoint (e1) never set these fields --
	// they must read back as the zero value (false/""), preserving
	// pre-Phase-3.18 behavior exactly.
	gotE1, err := s.Endpoints().Get(ctx, "e1")
	if err != nil {
		t.Fatalf("Get e1: %v", err)
	}
	if gotE1.APICandidate || gotE1.APIEvidence != "" || gotE1.ResponseContentType != "" {
		t.Errorf("e1 (predates API classification) = %+v, want all-zero API fields", gotE1)
	}
}

// TestParameter_Provenance_RoundTripAndDefault proves the migration's
// backward-compatibility guarantee directly: a Parameter created
// WITHOUT setting Provenance (as every pre-Phase-3.18 call site still
// does) reads back as "REQUEST_INPUT" -- the factually correct
// backfill, not an empty/undefined value -- and a Parameter that
// explicitly sets Provenance to "RESPONSE_FIELD" round-trips that
// value exactly.
func TestParameter_Provenance_RoundTripAndDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	seedForParameterTest(t, s, now)

	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-default", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", CreatedAt: now,
		// Provenance intentionally left unset.
	}); err != nil {
		t.Fatalf("create p-default: %v", err)
	}
	if err := s.Parameters().Create(ctx, models.Parameter{
		ID: "p-response", ScanJobID: "job1", EndpointID: "e1", Name: "user_id", Location: "json",
		Provenance: "RESPONSE_FIELD", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create p-response: %v", err)
	}

	gotDefault, err := s.Parameters().Get(ctx, "p-default")
	if err != nil {
		t.Fatalf("Get p-default: %v", err)
	}
	if gotDefault.Provenance != "REQUEST_INPUT" {
		t.Errorf("Provenance = %q, want REQUEST_INPUT for a Parameter created without setting it", gotDefault.Provenance)
	}

	gotResponse, err := s.Parameters().Get(ctx, "p-response")
	if err != nil {
		t.Fatalf("Get p-response: %v", err)
	}
	if gotResponse.Provenance != "RESPONSE_FIELD" {
		t.Errorf("Provenance = %q, want RESPONSE_FIELD", gotResponse.Provenance)
	}
}
