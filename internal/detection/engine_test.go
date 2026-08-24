// External test package: engine_test.go needs detectiontest.Mock, and
// detectiontest imports internal/detection itself (see that package's
// doc comment for why) -- an internal (package detection) test file
// importing detectiontest would therefore be an import cycle. Being in
// detection_test instead means everything from internal/detection used
// here must be exported, and the small test helpers the internal test
// files (registry_test.go, executor_test.go, targets_test.go) already
// have (fakeValidator, testServerTarget, newTestStore, seedRecon) are
// duplicated here in minimal form rather than shared, since Go test
// helpers aren't importable across a package boundary either.
package detection_test

import (
	"context"
	"log/slog"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detection/detectiontest"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

type fakeValidator struct{ allowed bool }

func (f *fakeValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) check() (scope.Decision, error) {
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	s, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type reconFixture struct {
	scanJobID string
	hostID    string
	serviceID string
	ip        string
	port      int
	url       string
	scheme    string
	endpoints []models.Endpoint
}

func seedRecon(t *testing.T, store storage.Store, f reconFixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

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
		e.ID = httpSvc.ID + "-ep" + strconv.Itoa(i)
		e.ScanJobID = f.scanJobID
		e.HTTPServiceID = httpSvc.ID
		e.CreatedAt = now
		if err := store.Endpoints().Create(ctx, e); err != nil {
			t.Fatalf("create endpoint: %v", err)
		}
	}
}

func testServerTarget(t *testing.T, srv *httptest.Server) detection.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("could not parse listener IP %q", host)
	}
	return detection.Target{Host: host, IP: ip, Port: port, Scheme: "http", URL: srv.URL, Path: "/"}
}

func newExecutor(allowed bool) *detection.Executor {
	return detection.NewExecutor(&fakeValidator{allowed: allowed}, dns.NewFakeResolver(), detection.ExecutorConfig{})
}

func TestEngine_NoDetectorsIsNotAnError(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	e := &detection.Engine{Registry: detection.NewRegistry(), Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.FindingsCreated != 0 || summary.DetectorRuns != 0 {
		t.Errorf("summary = %+v, want zero runs/findings with an empty registry", summary)
	}
}

func TestEngine_NoFindingResultCreatesNoFinding(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.NoFinding}
	if err := reg.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.DetectorRuns == 0 {
		t.Error("DetectorRuns = 0, want at least 1 (the mock detector should have run against the http_service target)")
	}
	if summary.FindingsCreated != 0 {
		t.Errorf("FindingsCreated = %d, want 0 -- \"not vulnerable\" must not create a finding", summary.FindingsCreated)
	}
	if len(summary.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", summary.Errors)
	}
}

func TestEngine_FindingIsNormalizedAndPersisted(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.Finding, Severity: models.SeverityHigh}
	_ = reg.Register(m)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.FindingsCreated != 1 {
		t.Fatalf("FindingsCreated = %d, want 1", summary.FindingsCreated)
	}

	persisted, err := store.Findings().ListByScanJob(context.Background(), "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(persisted) != 1 {
		t.Fatalf("persisted findings = %d, want 1", len(persisted))
	}
	f := persisted[0]
	if f.DetectorID != "mock-detector" {
		t.Errorf("DetectorID = %q, want mock-detector", f.DetectorID)
	}
	if f.ScanID != "job1" {
		t.Errorf("ScanID = %q, want job1", f.ScanID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Host == "" || f.URL == "" {
		t.Errorf("Host/URL were not filled in: %+v", f)
	}
	if len(f.Evidence) != 1 {
		t.Errorf("Evidence = %+v, want 1 item (the mock's structured evidence)", f.Evidence)
	}
}

func TestEngine_OnlyEligibleDetectorRunsAgainstMatchingTargetKind(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http",
		endpoints: []models.Endpoint{{Path: "/a?x=1", Method: "GET", Source: "crawl"}},
	})

	reg := detection.NewRegistry()
	// endpointOnly is only eligible for endpoint targets -- it must
	// never be invoked against the http_service-kind target this scan
	// job also produces.
	endpointOnly := &detectiontest.Mock{IDValue: "endpoint-only", TargetKinds: []detection.TargetKind{detection.TargetKindEndpoint}}
	_ = reg.Register(endpointOnly)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	targets, _ := detection.BuildTargets(context.Background(), store, "job1")
	var endpointTargetCount int
	for _, tgt := range targets {
		if tgt.Kind == detection.TargetKindEndpoint {
			endpointTargetCount++
		}
	}
	if int(endpointOnly.Calls()) != endpointTargetCount {
		t.Errorf("endpointOnly.Calls() = %d, want exactly %d (one per endpoint-kind target, none for the http_service target)", endpointOnly.Calls(), endpointTargetCount)
	}
}

func TestEngine_EligibleFuncFiltersFurtherThanMetadata(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{EligibleFunc: func(detection.Target) bool { return false }}
	_ = reg.Register(m)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if m.Calls() != 0 {
		t.Errorf("Calls() = %d, want 0 -- Eligible returning false must prevent Detect from ever being called", m.Calls())
	}
	if summary.DetectorRuns != 0 {
		t.Errorf("DetectorRuns = %d, want 0", summary.DetectorRuns)
	}
}

func TestEngine_DisabledDetectorNeverRuns(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.Finding}
	_ = reg.Register(m)
	if err := reg.SetEnabled(m.Metadata().ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if m.Calls() != 0 || summary.FindingsCreated != 0 {
		t.Errorf("a disabled detector ran: calls=%d findingsCreated=%d", m.Calls(), summary.FindingsCreated)
	}
}

func TestEngine_DetectorErrorDoesNotStopOtherDetectors(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	failing := &detectiontest.Mock{IDValue: "failing", Behavior: detectiontest.Error}
	working := &detectiontest.Mock{IDValue: "working", Behavior: detectiontest.Finding}
	_ = reg.Register(failing)
	_ = reg.Register(working)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.FindingsCreated != 1 {
		t.Errorf("FindingsCreated = %d, want 1 (the working detector's finding, despite the other detector erroring)", summary.FindingsCreated)
	}
	if len(summary.Errors) != 1 {
		t.Fatalf("Errors = %+v, want exactly 1", summary.Errors)
	}
	if summary.Errors[0].DetectorID != "failing" {
		t.Errorf("Errors[0].DetectorID = %q, want failing", summary.Errors[0].DetectorID)
	}
}

func TestEngine_DetectorPanicIsRecoveredAndDoesNotCrashTheRun(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	panicky := &detectiontest.Mock{IDValue: "panicky", Behavior: detectiontest.Panic}
	working := &detectiontest.Mock{IDValue: "working", Behavior: detectiontest.Finding}
	_ = reg.Register(panicky)
	_ = reg.Register(working)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v (a detector panic must not surface as Run's own error)", err)
	}
	if summary.FindingsCreated != 1 {
		t.Errorf("FindingsCreated = %d, want 1", summary.FindingsCreated)
	}
	foundPanicError := false
	for _, e := range summary.Errors {
		if e.DetectorID == "panicky" {
			foundPanicError = true
		}
	}
	if !foundPanicError {
		t.Errorf("Errors = %+v, want an entry for the panicking detector", summary.Errors)
	}
}

func TestEngine_ScopeEnforcedThroughExecutor(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { hits++ }))
	defer srv.Close()

	store := newTestStore(t)
	tgt := testServerTarget(t, srv)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: tgt.IP.String(), port: tgt.Port, url: tgt.URL + "/", scheme: "http"})

	reg := detection.NewRegistry()
	// The mock issues a real request through the Executor -- with a
	// denying validator, that request must never reach the server, and
	// the detector's own Detect call must surface it as an error (not a
	// finding, not a silent success).
	m := &detectiontest.Mock{RequestPath: "probe", Behavior: detectiontest.NoFinding}
	_ = reg.Register(m)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(false), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits != 0 {
		t.Errorf("server received %d requests, want 0 -- scope denial must prevent the dial entirely", hits)
	}
	if len(summary.Errors) == 0 {
		t.Error("want a detector error recording the scope denial, got none")
	}
	if summary.FindingsCreated != 0 {
		t.Errorf("FindingsCreated = %d, want 0", summary.FindingsCreated)
	}
}

func TestEngine_CancellationStopsBeforeAllTargetsRun(t *testing.T) {
	store := newTestStore(t)
	// Many endpoint targets, each requiring a Detect call that sleeps --
	// enough that a short deadline guarantees not every one completes.
	var endpoints []models.Endpoint
	for i := 0; i < 20; i++ {
		endpoints = append(endpoints, models.Endpoint{Path: "/p" + strconv.Itoa(i), Method: "GET", Source: "crawl"})
	}
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http", endpoints: endpoints})

	reg := detection.NewRegistry()
	slow := &detectiontest.Mock{DetectDelay: 200 * time.Millisecond}
	_ = reg.Register(slow)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Concurrency: 2, Logger: discardLogger()}
	summary, err := e.Run(ctx, detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !summary.Cancelled {
		t.Error("summary.Cancelled = false, want true")
	}
	if int(slow.Calls()) >= 21 { // 20 endpoint targets + 1 http_service target
		t.Errorf("slow.Calls() = %d, want fewer than the full target count -- cancellation should have stopped new work from starting", slow.Calls())
	}
}

func TestEngine_ConcurrentExecutionUnderRace(t *testing.T) {
	store := newTestStore(t)
	var endpoints []models.Endpoint
	for i := 0; i < 30; i++ {
		endpoints = append(endpoints, models.Endpoint{Path: "/p" + strconv.Itoa(i), Method: "GET", Source: "crawl"})
	}
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http", endpoints: endpoints})

	reg := detection.NewRegistry()
	fast := &detectiontest.Mock{Behavior: detectiontest.Finding}
	_ = reg.Register(fast)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Concurrency: 8, Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Just assert the run completed cleanly under -race with many
	// concurrent detector calls and produced a sane result -- the race
	// detector itself is what actually proves thread-safety here.
	if summary.FindingsCreated == 0 {
		t.Error("FindingsCreated = 0, want at least 1")
	}
	if len(summary.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", summary.Errors)
	}
}

func TestEngine_RerunIsIdempotentViaDeduplication(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.Finding}
	_ = reg.Register(m)

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}

	first, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.FindingsCreated != 1 {
		t.Fatalf("first run FindingsCreated = %d, want 1", first.FindingsCreated)
	}

	second, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if second.FindingsCreated != 0 {
		t.Errorf("second run FindingsCreated = %d, want 0 (already on record)", second.FindingsCreated)
	}
	if second.Duplicates == 0 {
		t.Error("second run Duplicates = 0, want at least 1")
	}

	all, _ := store.Findings().ListByScanJob(context.Background(), "job1")
	if len(all) != 1 {
		t.Errorf("total persisted findings = %d, want 1 (re-running detection must not duplicate storage rows)", len(all))
	}
}
