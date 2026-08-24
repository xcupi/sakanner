package detection

import (
	"context"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// newTestStore returns an in-memory sqlite Store, migrated and ready,
// closed automatically at test cleanup -- the same pattern
// internal/storage/sqlite's own tests and lab use.
func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	s, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// reconFixture is what seedRecon needs to build one HTTPService (plus
// optional Endpoints) worth of Phase 2 recon data for a scan job.
type reconFixture struct {
	scanJobID string
	hostID    string
	serviceID string
	ip        string
	port      int
	url       string
	scheme    string
	endpoints []models.Endpoint // Path/Method/Source only; ID/ScanJobID/HTTPServiceID filled in
	techs     []models.Technology
}

// seedRecon persists exactly the recon rows BuildTargets reads --
// Host, Service, HTTPService, Endpoints, Technologies -- for one
// fixture, returning the persisted HTTPService's ID.
func seedRecon(t *testing.T, store storage.Store, f reconFixture) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	// Ensure the scan job and its asset exist -- hosts/services/etc. all
	// carry foreign keys back to them. Create is idempotent-enough for
	// this helper's purposes: each test uses a distinct scanJobID/hostID,
	// and a job row is only ever created once per test.
	if _, err := store.ScanJobs().Get(ctx, f.scanJobID); err != nil {
		if err := store.ScanJobs().Create(ctx, models.ScanJob{ID: f.scanJobID, Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}); err != nil {
			t.Fatalf("create scan job: %v", err)
		}
	}
	if err := store.Assets().Create(ctx, models.Asset{ID: "asset-" + f.hostID, ScanJobID: f.scanJobID, Name: f.url, Source: "test", CreatedAt: now}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := store.Hosts().Create(ctx, models.Host{ID: f.hostID, ScanJobID: f.scanJobID, AssetID: "asset-" + f.hostID, IPAddress: f.ip, CreatedAt: now}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := store.Services().Create(ctx, models.Service{ID: f.serviceID, ScanJobID: f.scanJobID, HostID: f.hostID, Port: f.port, Protocol: "tcp", CreatedAt: now}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "http-" + f.serviceID, ScanJobID: f.scanJobID, ServiceID: f.serviceID, URL: f.url, Scheme: f.scheme, StatusCode: 200, CreatedAt: now}
	if err := store.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	for i, e := range f.endpoints {
		e.ID = httpSvc.ID + "-ep" + string(rune('a'+i))
		e.ScanJobID = f.scanJobID
		e.HTTPServiceID = httpSvc.ID
		e.CreatedAt = now
		if err := store.Endpoints().Create(ctx, e); err != nil {
			t.Fatalf("create endpoint: %v", err)
		}
	}
	for i, tech := range f.techs {
		tech.ID = httpSvc.ID + "-tech" + string(rune('a'+i))
		tech.ScanJobID = f.scanJobID
		tech.HTTPServiceID = httpSvc.ID
		tech.CreatedAt = now
		if err := store.Technologies().Create(ctx, tech); err != nil {
			t.Fatalf("create technology: %v", err)
		}
	}
	return httpSvc.ID
}

func TestBuildTargets_OneTargetPerHTTPService(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 8080, url: "http://vuln.scanner.test:8080/", scheme: "http",
	})

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}

	var httpServiceTargets int
	for _, tgt := range targets {
		if tgt.Kind != TargetKindHTTPService {
			continue
		}
		httpServiceTargets++
		if tgt.HTTPServiceID != httpSvcID {
			t.Errorf("HTTPServiceID = %q, want %q", tgt.HTTPServiceID, httpSvcID)
		}
		if tgt.Host != "vuln.scanner.test" || tgt.Port != 8080 {
			t.Errorf("Host/Port = %q/%d, want vuln.scanner.test/8080", tgt.Host, tgt.Port)
		}
		if tgt.IP == nil || tgt.IP.String() != "127.0.0.21" {
			t.Errorf("IP = %v, want 127.0.0.21", tgt.IP)
		}
		if tgt.Path != "/" {
			t.Errorf("Path = %q, want /", tgt.Path)
		}
	}
	if httpServiceTargets != 1 {
		t.Errorf("got %d http_service targets, want 1", httpServiceTargets)
	}
}

func TestBuildTargets_EndpointAndParameterTargets(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/xss/reflected/vulnerable?q=hello", Method: "GET", Source: "crawl"},
		},
	})
	// Phase 3.13: BuildTargets sources query-parameter targets from the
	// persisted Parameters store (what internal/orchestration's input
	// discovery stage would already have written), not by live-reparsing
	// the endpoint's own path -- so this fixture must seed the
	// equivalent Parameter row itself, mirroring exactly what
	// parameters.Normalize + persistence would have produced for this
	// endpoint.
	endpointID := httpSvcID + "-epa" // matches seedRecon's own e.ID formula for the first (only) endpoint
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "param1", ScanJobID: "job1", EndpointID: endpointID,
		Name: "q", Location: "query", Classification: "PARAMETER", Method: "GET", Value: "hello", Source: "url_query",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}

	var endpointTarget, paramTarget *Target
	for i := range targets {
		tgt := targets[i]
		if tgt.Kind != TargetKindEndpoint {
			continue
		}
		if tgt.Parameter == "" {
			endpointTarget = &targets[i]
		} else {
			paramTarget = &targets[i]
		}
	}

	if endpointTarget == nil {
		t.Fatal("no plain endpoint target was built")
	}
	if endpointTarget.Path != "/xss/reflected/vulnerable" {
		t.Errorf("endpoint Path = %q, want /xss/reflected/vulnerable (query stripped)", endpointTarget.Path)
	}
	if endpointTarget.Method != "GET" {
		t.Errorf("endpoint Method = %q, want GET", endpointTarget.Method)
	}

	if paramTarget == nil {
		t.Fatal("no parameter target was built from the endpoint's query string")
	}
	if paramTarget.Parameter != "q" {
		t.Errorf("Parameter = %q, want q", paramTarget.Parameter)
	}
	if paramTarget.ParameterLocation != "query" {
		t.Errorf("ParameterLocation = %q, want query", paramTarget.ParameterLocation)
	}
}

// TestBuildTargets_IdentityContext_PropagatesFromEndpoint is Phase
// 3.16's own addition: BuildTargets must copy an Endpoint's own
// IdentityContext onto every Target built from it (both the plain
// endpoint target and its derived query-parameter targets), and leave
// it empty for a target with none -- task section 15's "future
// detectors can ask under which identity a request was made" applied
// concretely.
func TestBuildTargets_IdentityContext_PropagatesFromEndpoint(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/account?resource_id=5", Method: "GET", Source: "crawl", IdentityContext: "account-a"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "param1", ScanJobID: "job1", EndpointID: endpointID,
		Name: "resource_id", Location: "query", Classification: "PARAMETER", Method: "GET", Value: "5", Source: "url_query",
		IdentityContext: "account-a", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}

	sawEndpoint, sawParam, sawHTTPService := false, false, false
	for _, tgt := range targets {
		switch {
		case tgt.Kind == TargetKindHTTPService:
			sawHTTPService = true
			if tgt.IdentityContext != "" {
				t.Errorf("HTTPService target IdentityContext = %q, want empty (the probe stage is never authenticated)", tgt.IdentityContext)
			}
		case tgt.Kind == TargetKindEndpoint && tgt.Parameter == "":
			sawEndpoint = true
			if tgt.IdentityContext != "account-a" {
				t.Errorf("endpoint target IdentityContext = %q, want account-a", tgt.IdentityContext)
			}
		case tgt.Kind == TargetKindEndpoint && tgt.Parameter != "":
			sawParam = true
			if tgt.IdentityContext != "account-a" {
				t.Errorf("parameter target IdentityContext = %q, want account-a", tgt.IdentityContext)
			}
		}
	}
	if !sawEndpoint || !sawParam || !sawHTTPService {
		t.Fatalf("did not observe all three target kinds: endpoint=%v param=%v httpService=%v", sawEndpoint, sawParam, sawHTTPService)
	}
}

// TestBuildTargets_NoParameterRows_NoParameterTargets pins down the
// Phase 3.13 architecture change directly: a query string literally
// present in Endpoint.Path is NOT, by itself, enough to produce a
// parameter Target anymore -- only a persisted Parameter row does.
// Query-string extraction now happens once, during input discovery
// (internal/orchestration), not by BuildTargets re-parsing raw URLs.
func TestBuildTargets_NoParameterRows_NoParameterTargets(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/xss/reflected/vulnerable?q=hello", Method: "GET", Source: "crawl"},
		},
	})

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Parameter != "" {
			t.Errorf("got a parameter target %+v with no Parameter row ever persisted", tgt)
		}
	}
}

// TestBuildTargets_NonQueryLocationParameters_NoTargets is task's
// "Existing detectors should not have to parse... themselves" +
// "detector compatibility" boundary made explicit: a form/JSON-body
// parameter is discovered and persisted, but does not produce a
// detection Target, since every real detector requires
// ParameterLocation == "query" exactly (see BuildTargets' doc
// comment).
// TestBuildTargets_PathRequestInputParameter_BecomesPathTarget proves
// Phase 3.23's new eligibility: a path-location parameter with
// Provenance == "REQUEST_INPUT" (or unset, which the storage layer's
// own Create defaults to "REQUEST_INPUT", the same established
// backward-compatibility convention Phase 3.18 set for JSON and Phase
// 3.21 for form) becomes a Target with ParameterLocation == "path",
// carrying PathSegmentIndex. Renamed from
// TestBuildTargets_PathLocationParameter_NoTargets, whose own
// assertion this phase deliberately reverses -- see
// docs/phase-3-23-path-parameters.md section 5 -- exactly mirroring
// how Phase 3.19/3.21 evolved this same test's own earlier ancestors
// for JSON and form.
func TestBuildTargets_PathRequestInputParameter_BecomesPathTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/users/123", Method: "GET", Source: "crawl"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-path", ScanJobID: "job1", EndpointID: endpointID, Name: "user_id", Location: "path", Method: "GET",
		Value: "123", PathSegmentIndex: 1, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var found *Target
	for i, tgt := range targets {
		if tgt.Parameter == "user_id" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatal("expected a Target for the REQUEST_INPUT-provenance path parameter 'user_id'")
	}
	if found.ParameterLocation != "path" {
		t.Errorf("ParameterLocation = %q, want path", found.ParameterLocation)
	}
	if found.PathSegmentIndex != 1 {
		t.Errorf("PathSegmentIndex = %d, want 1", found.PathSegmentIndex)
	}
}

// TestBuildTargets_PathResponseFieldParameter_NoTarget proves the
// same REQUEST_INPUT/RESPONSE_FIELD distinction already enforced for
// JSON also holds for path -- even though no live source ever
// produces a RESPONSE_FIELD path candidate today, the filter is
// tested explicitly rather than assumed unreachable.
func TestBuildTargets_PathResponseFieldParameter_NoTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/users/123", Method: "GET", Source: "crawl"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-path", ScanJobID: "job1", EndpointID: endpointID, Name: "user_id", Location: "path", Method: "GET",
		Value: "123", PathSegmentIndex: 1, Provenance: "RESPONSE_FIELD", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Parameter == "user_id" {
			t.Errorf("SECURITY: a RESPONSE_FIELD-provenance path parameter became a Target: %+v", tgt)
		}
	}
}

// TestBuildTargets_FormRequestInputParameter_BecomesFormTarget proves
// Phase 3.21's new eligibility: a form-location parameter with
// Provenance == "REQUEST_INPUT" (or unset, which the storage layer's
// own Create defaults to "REQUEST_INPUT", the same established
// backward-compatibility convention Phase 3.18 set for JSON) on a
// same-origin form endpoint (ActionOrigin == "", the default -- the
// common case: an endpoint created without ActionOrigin set is
// treated as same-origin, matching every endpoint discovered before
// this migration existed) becomes a Target with ParameterLocation ==
// "form", carrying FormFields with every sibling field's value.
func TestBuildTargets_FormRequestInputParameter_BecomesFormTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/login", Method: "POST", Source: "form"},
		},
	})
	endpointID := httpSvcID + "-epa"
	for _, prm := range []models.Parameter{
		{ID: "p-username", ScanJobID: "job1", EndpointID: endpointID, Name: "username", Value: "alice", Location: "form", Method: "POST", ContentType: "application/x-www-form-urlencoded", CreatedAt: time.Now().UTC()},
		{ID: "p-csrf", ScanJobID: "job1", EndpointID: endpointID, Name: "csrf_token", Value: "<REDACTED>", Location: "form", Method: "POST", ContentType: "application/x-www-form-urlencoded", CreatedAt: time.Now().UTC()},
	} {
		if err := store.Parameters().Create(context.Background(), prm); err != nil {
			t.Fatalf("create parameter %s: %v", prm.ID, err)
		}
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var usernameTarget *Target
	for i, tgt := range targets {
		if tgt.Parameter == "csrf_token" {
			t.Errorf("csrf_token was promoted to its own Target -- security-token fields must never be independently targeted: %+v", tgt)
		}
		if tgt.Parameter == "username" {
			usernameTarget = &targets[i]
		}
	}
	if usernameTarget == nil {
		t.Fatal("expected a Target for the REQUEST_INPUT-provenance form parameter 'username'")
	}
	if usernameTarget.ParameterLocation != "form" {
		t.Errorf("ParameterLocation = %q, want form", usernameTarget.ParameterLocation)
	}
	if got := usernameTarget.FormFields["username"]; got != "alice" {
		t.Errorf("FormFields[username] = %q, want alice", got)
	}
	if got := usernameTarget.FormFields["csrf_token"]; got != "<REDACTED>" {
		t.Errorf("FormFields[csrf_token] = %q, want the preserved (redacted) sibling value, got %q", got, got)
	}
}

// TestBuildTargets_FormCrossOriginAction_TargetsRealDestinationWithNilIP
// proves Phase 3.22's resolution of Finding 3 (docs/phase-3-22-active-detection-coverage.md
// section 7): a form endpoint whose ActionOrigin differs from its own
// HTTPService's origin now DOES produce a Target -- but pointed at the
// PARSED ActionOrigin's own Host/Scheme/Port, with IP left nil so
// mutation.Executor resolves and scope-validates it FRESH at execution
// time, rather than being silently dialed against the wrong
// (same-origin) host or silently excluded outright (Phase 3.21's own,
// now-superseded, behavior).
func TestBuildTargets_FormCrossOriginAction_TargetsRealDestinationWithNilIP(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/steal", Method: "POST", Source: "form", ActionOrigin: "http://external.scanner.test:80"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-username", ScanJobID: "job1", EndpointID: endpointID, Name: "username", Location: "form", Method: "POST", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var found *Target
	for i, tgt := range targets {
		if tgt.Parameter == "username" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatal("expected a Target for the cross-origin form's 'username' field, targeting its real destination")
	}
	if found.Host != "external.scanner.test" || found.Port != 80 || found.Scheme != "http" {
		t.Errorf("Target = {Host:%q Port:%d Scheme:%q}, want {external.scanner.test 80 http}", found.Host, found.Port, found.Scheme)
	}
	if found.IP != nil {
		t.Errorf("IP = %v, want nil (must be resolved and scope-validated FRESH at execution time, never reuse this HTTPService's own already-resolved IP)", found.IP)
	}
}

// TestBuildTargets_FormMalformedActionOrigin_NoTarget proves the
// defensive fallback: an unparseable ActionOrigin never becomes a
// guessed Target -- it falls back to Phase 3.21's original skip
// behavior for that endpoint's query/form parameters specifically.
func TestBuildTargets_FormMalformedActionOrigin_NoTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/steal", Method: "POST", Source: "form", ActionOrigin: "not-a-valid-origin"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-username", ScanJobID: "job1", EndpointID: endpointID, Name: "username", Location: "form", Method: "POST", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Parameter == "username" {
			t.Fatalf("a malformed ActionOrigin must never produce a guessed Target: %+v", tgt)
		}
	}
}

// TestBuildTargets_GETFormQueryParameter_CrossOrigin_TargetsRealDestination
// proves the same Phase 3.22 resolution also applies to a GET form's
// query-location fields (Finding 3 affected both, not just POST
// forms).
func TestBuildTargets_GETFormQueryParameter_CrossOrigin_TargetsRealDestination(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{
			{Path: "/search", Method: "GET", Source: "form", ActionOrigin: "http://external.scanner.test:80"},
		},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-q", ScanJobID: "job1", EndpointID: endpointID, Name: "q", Location: "query", Method: "GET", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var found *Target
	for i, tgt := range targets {
		if tgt.Parameter == "q" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatal("expected a Target for the cross-origin GET form's 'q' field, targeting its real destination")
	}
	if found.Host != "external.scanner.test" || found.IP != nil {
		t.Errorf("Target = {Host:%q IP:%v}, want {external.scanner.test <nil>}", found.Host, found.IP)
	}
}

// TestBuildTargets_JSONResponseFieldParameter_NoTarget proves a JSON
// parameter with Provenance == "RESPONSE_FIELD" (Phase 3.18 -- a field
// only ever observed in a response, never confirmed accepted as an
// input) is deliberately excluded from target selection, even though
// its Location is "json" -- task section 18's own "response field !=
// request parameter" distinction, enforced at the one place JSON
// parameters are allowed to become active-detection Targets at all.
func TestBuildTargets_JSONResponseFieldParameter_NoTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{{Path: "/api/data", Method: "GET", Source: "crawl"}},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-response", ScanJobID: "job1", EndpointID: endpointID, Name: "user_id", Location: "json",
		Method: "GET", Provenance: "RESPONSE_FIELD", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Parameter == "user_id" {
			t.Fatalf("SECURITY: a RESPONSE_FIELD-provenance JSON parameter produced a mutation-eligible Target: %+v", tgt)
		}
	}
}

// TestBuildTargets_JSONRequestInputParameter_BecomesBodyTarget proves
// the new Phase 3.19 eligibility: a JSON-location parameter with
// Provenance == "REQUEST_INPUT" (or unset, which the storage layer's
// own Create defaults to "REQUEST_INPUT" -- Phase 3.18's established
// backward-compatibility convention) becomes a Target with
// ParameterLocation == "body".
func TestBuildTargets_JSONRequestInputParameter_BecomesBodyTarget(t *testing.T) {
	store := newTestStore(t)
	httpSvcID := seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		endpoints: []models.Endpoint{{Path: "/api/echo", Method: "POST", Source: "crawl"}},
	})
	endpointID := httpSvcID + "-epa"
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-request", ScanJobID: "job1", EndpointID: endpointID, Name: "role", Location: "json",
		Method: "POST", Provenance: "REQUEST_INPUT", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	found := false
	for _, tgt := range targets {
		if tgt.Parameter == "role" {
			found = true
			if tgt.ParameterLocation != "body" {
				t.Errorf("ParameterLocation = %q, want body", tgt.ParameterLocation)
			}
		}
	}
	if !found {
		t.Fatal("expected a Target for the REQUEST_INPUT-provenance JSON parameter 'role'")
	}
}

func TestBuildTargets_TechnologiesAttachedToHTTPServiceTarget(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "host1", serviceID: "svc1",
		ip: "127.0.0.21", port: 80, url: "http://vuln.scanner.test/", scheme: "http",
		techs: []models.Technology{{Name: "jQuery", Version: "1.6.1"}},
	})

	targets, err := BuildTargets(context.Background(), store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Kind != TargetKindHTTPService {
			continue
		}
		if len(tgt.Technologies) != 1 || tgt.Technologies[0].Name != "jQuery" {
			t.Errorf("Technologies = %+v, want [{jQuery 1.6.1}]", tgt.Technologies)
		}
	}
}

func TestBuildTargets_SkipsServiceWithNoResolvedIP(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.ScanJobs().Create(ctx, models.ScanJob{ID: "job1", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	if err := store.Assets().Create(ctx, models.Asset{ID: "asset-orphan", ScanJobID: "job1", Name: "orphan.test", Source: "test", CreatedAt: now}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	// A Host row on record with an empty/unparseable IP address (e.g. a
	// resolution that was recorded but never actually produced a usable
	// address) -- BuildTargets must skip the service built on top of it
	// rather than producing a Target with a nil IP that Executor.Do
	// would then have to reject at request time.
	if err := store.Hosts().Create(ctx, models.Host{ID: "host-orphan", ScanJobID: "job1", AssetID: "asset-orphan", IPAddress: "", CreatedAt: now}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := store.Services().Create(ctx, models.Service{ID: "svc-orphan", ScanJobID: "job1", HostID: "host-orphan", Port: 80, Protocol: "tcp", CreatedAt: now}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := store.HTTPServices().Create(ctx, models.HTTPService{ID: "http-orphan", ScanJobID: "job1", ServiceID: "svc-orphan", URL: "http://orphan.test/", Scheme: "http", StatusCode: 200, CreatedAt: now}); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	targets, err := BuildTargets(ctx, store, "job1")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("BuildTargets = %+v, want empty (no resolvable IP for the only service)", targets)
	}
}

func TestBuildTargets_EmptyScanJobReturnsNoTargets(t *testing.T) {
	store := newTestStore(t)
	targets, err := BuildTargets(context.Background(), store, "no-such-job")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("BuildTargets for a job with no recon data = %+v, want empty", targets)
	}
}
