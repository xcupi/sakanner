package orchestrator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file covers Phase 3.12's two new per-scan Options fields
// (DetectionDisabled, CrawlOverride) and the Result.Profile field --
// the mechanism internal/policy.Resolve's effective policy is
// translated into. See buildOrchestratorAgainstRealStore in
// detection_state_test.go (reused here, unmodified) for the shared
// test-fixture pattern.

func parameterizedTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/search?q=hello">search</a></body></html>`))
	}))
}

// TestOptions_DetectionDisabled_SkipsDetectionEntirely is the core
// "recon profile" safety property: with DetectionDisabled=true against
// a target that DOES have a crawlable, parameterized endpoint (i.e.
// detection would otherwise run and find something eligible), the
// detection engine must never even be invoked -- state
// DISABLED_BY_PROFILE, zero eligible targets, zero detector runs, zero
// detection-issued requests, and (unlike state B) no warning recorded
// at all, since this is expected, policy-driven behavior.
func TestOptions_DetectionDisabled_SkipsDetectionEntirely(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	// Crawler enabled at the Pipeline level -- proves DetectionDisabled
	// alone (not "no eligible targets") is what stops detection: a
	// crawlable, parameterized endpoint genuinely exists here.
	orch := buildOrchestratorAgainstRealStore(t, srv, true)
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1", DetectionDisabled: true})
	if err != nil {
		t.Fatalf("Run: %v (status=%s errors=%+v)", err, result.Status, result.Errors)
	}

	if result.ReconSummary.EndpointCount == 0 {
		t.Fatal("test fixture invalid: crawler found no endpoints, so this test cannot distinguish DetectionDisabled from NotRun")
	}
	ds := result.DetectorSummary
	if ds.State != DetectionStateDisabledByProfile {
		t.Errorf("DetectionState = %s, want DETECTION_DISABLED_BY_PROFILE", ds.State)
	}
	if ds.EligibleTargets != 0 {
		t.Errorf("EligibleTargets = %d, want 0 (detection never ran)", ds.EligibleTargets)
	}
	if ds.DetectorRuns != 0 {
		t.Errorf("DetectorRuns = %d, want 0", ds.DetectorRuns)
	}
	if ds.RequestsIssued != 0 {
		t.Errorf("RequestsIssued = %d, want 0 -- detection must never issue a single request when disabled", ds.RequestsIssued)
	}
	if result.Status != StatusCompleted {
		t.Errorf("Status = %s, want COMPLETED (a disabled-by-profile scan is not a warning condition)", result.Status)
	}
	for _, w := range result.Warnings {
		if strings.Contains(w, "DETECTION_NOT_RUN") {
			t.Errorf("unexpected DETECTION_NOT_RUN warning on a DetectionDisabled scan: %q", w)
		}
	}
}

// TestOptions_DetectionDisabled_ZeroValue_RunsDetectionAsBefore pins
// down backward compatibility: Options{} (DetectionDisabled's Go zero
// value, false) must behave exactly like every pre-Phase-3.12 caller
// already relies on -- detection attempted normally.
func TestOptions_DetectionDisabled_ZeroValue_RunsDetectionAsBefore(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, true)
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.DetectorSummary.State != DetectionStateExecuted {
		t.Errorf("DetectionState = %s, want EXECUTED (zero-value Options must not disable detection)", result.DetectorSummary.State)
	}
	if result.Profile != "" {
		t.Errorf("Result.Profile = %q, want empty for zero-value Options", result.Profile)
	}
}

// TestOptions_CrawlOverride_EnablesCrawlingDespitePipelineDisabled
// proves CrawlOverride actually takes effect (a "web"/"deep"-style
// scan against an Orchestrator whose Pipeline itself has crawling
// off).
func TestOptions_CrawlOverride_EnablesCrawlingDespitePipelineDisabled(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false) // Pipeline-level: crawler OFF
	result, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 10},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ReconSummary.EndpointCount == 0 {
		t.Error("CrawlOverride{Enabled: true} did not produce any discovered endpoints despite a crawlable link existing")
	}
	if result.DetectorSummary.State != DetectionStateExecuted {
		t.Errorf("DetectionState = %s, want EXECUTED (override should have made the endpoint eligible)", result.DetectorSummary.State)
	}
}

// TestOptions_CrawlOverride_DisablesCrawlingDespitePipelineEnabled is
// the mirror image: a "recon"-style override on an Orchestrator whose
// Pipeline itself has crawling on must still suppress crawling for
// THIS scan.
func TestOptions_CrawlOverride_DisablesCrawlingDespitePipelineEnabled(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, true) // Pipeline-level: crawler ON
	result, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: false},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ReconSummary.EndpointCount != 0 {
		t.Errorf("CrawlOverride{Enabled: false} still produced %d endpoints, want 0", result.ReconSummary.EndpointCount)
	}
}

// TestOptions_CrawlOverride_DoesNotMutateSharedPipeline: after a scan
// using CrawlOverride, the Orchestrator's own o.Pipeline fields must be
// completely unchanged -- Options.CrawlOverride's doc comment promises
// a per-scan COPY, never a mutation of shared state, which is what
// makes concurrent differently-profiled scans against one Orchestrator
// safe in the first place.
func TestOptions_CrawlOverride_DoesNotMutateSharedPipeline(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false)
	before := *orch.Pipeline
	_, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 4, MaxPages: 75},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	after := *orch.Pipeline
	if before.CrawlEnabled != after.CrawlEnabled || before.CrawlMaxDepth != after.CrawlMaxDepth || before.CrawlMaxPages != after.CrawlMaxPages {
		t.Errorf("o.Pipeline's own crawl settings were mutated by a scan using CrawlOverride: before=%+v after crawl fields=(%v,%d,%d)",
			before, after.CrawlEnabled, after.CrawlMaxDepth, after.CrawlMaxPages)
	}
}

// TestOptions_ConcurrentScans_DifferentProfiles_NoCrossContamination
// is task's "concurrent scans using different profiles" / "profile
// isolation" requirement at the programmatic level: ONE shared
// Orchestrator instance runs a recon-style (DetectionDisabled, crawler
// off) scan and a web-style (crawler on, detection on) scan
// concurrently, against two independent targets sharing the same
// scope-allowed host but different ports. Neither scan's policy may
// leak into the other's result.
func TestOptions_ConcurrentScans_DifferentProfiles_NoCrossContamination(t *testing.T) {
	reconSrv := parameterizedTestServer()
	defer reconSrv.Close()
	webSrv := parameterizedTestServer()
	defer webSrv.Close()

	// buildOrchestratorAgainstRealStore pins DefaultPorts to ONE
	// server's port; Options.Ports overrides it per call, so both
	// servers are reachable from the same shared Orchestrator/Pipeline.
	orch := buildOrchestratorAgainstRealStore(t, reconSrv, false)
	webPort := portOf(t, webSrv)

	var wg sync.WaitGroup
	var reconResult, webResult Result
	var reconErr, webErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		reconResult, reconErr = orch.Run(context.Background(), Options{
			Target:            "127.0.0.1",
			ProfileLabel:      "recon",
			DetectionDisabled: true,
			CrawlOverride:     &CrawlSettings{Enabled: false},
		})
	}()
	go func() {
		defer wg.Done()
		webResult, webErr = orch.Run(context.Background(), Options{
			Target:        "127.0.0.1",
			Ports:         []int{webPort},
			ProfileLabel:  "web",
			CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 10},
		})
	}()
	wg.Wait()

	if reconErr != nil {
		t.Fatalf("recon-style Run: %v", reconErr)
	}
	if webErr != nil {
		t.Fatalf("web-style Run: %v", webErr)
	}

	if reconResult.Profile != "recon" {
		t.Errorf("recon-style scan Result.Profile = %q, want \"recon\"", reconResult.Profile)
	}
	if reconResult.DetectorSummary.State != DetectionStateDisabledByProfile {
		t.Errorf("recon-style scan DetectionState = %s, want DETECTION_DISABLED_BY_PROFILE", reconResult.DetectorSummary.State)
	}
	if reconResult.ReconSummary.EndpointCount != 0 {
		t.Errorf("recon-style scan discovered %d endpoints, want 0 (crawler should have been off)", reconResult.ReconSummary.EndpointCount)
	}

	if webResult.Profile != "web" {
		t.Errorf("web-style scan Result.Profile = %q, want \"web\"", webResult.Profile)
	}
	if webResult.DetectorSummary.State != DetectionStateExecuted {
		t.Errorf("web-style scan DetectionState = %s, want EXECUTED", webResult.DetectorSummary.State)
	}
	if webResult.ReconSummary.EndpointCount == 0 {
		t.Error("web-style scan discovered 0 endpoints, want at least 1 (crawler should have been on)")
	}
}

// TestScanTimeout_PositiveButNotExceeded_DoesNotFalselyReportCancelled
// pins down a real bug Phase 3.12 uncovered (see Run's own ctxDone doc
// comment): Limits.ScanTimeout was virtually always 0 ("no timeout")
// in every pre-3.12 caller, so a latent defer-ordering hazard around
// releasing that context's timer was never exercised -- Phase 3.12's
// profile resolution is the first thing to give the CLI a real,
// positive ScanTimeout by default, which immediately turned every
// completed scan CANCELLED. A scan that finishes well within a
// generous timeout must report its true status, never CANCELLED
// merely because a positive timeout was configured.
func TestScanTimeout_PositiveButNotExceeded_DoesNotFalselyReportCancelled(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, true)
	orch.Limits.ScanTimeout = 5 * time.Minute // generous, matching a real profile's own default
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status == StatusCancelled {
		t.Fatal("Status = CANCELLED despite completing well within a 5-minute ScanTimeout -- regression of the ScanTimeout cleanup-ordering bug")
	}
	if result.DetectorSummary.State != DetectionStateExecuted {
		t.Errorf("DetectionState = %s, want EXECUTED", result.DetectorSummary.State)
	}
}

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type: %T", srv.Listener.Addr())
	}
	return addr.Port
}
