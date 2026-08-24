package orchestrator

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func discardTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Phase 3.11.2 task section 5: the 3 detection states must never be
// conflated. States A (executed) and B (not run, no eligible targets)
// are already exercised end to end by lab/phase3_11_orchestrator_test.go
// against the real vuln lab; this file covers state C (execution
// failed) at the unit level, since reliably forcing a hard
// detection.Engine.Run failure needs a storage double, not a real
// target.

// failingServicesStore wraps a real storage.Store, delegating
// everything except Services(), whose ListByScanJob always errors --
// forcing detection.BuildTargets (called first thing inside
// Engine.Run) to fail deterministically, without needing any real
// vulnerable content or a registered detector at all.
type failingServicesStore struct {
	storage.Store
}

func (f failingServicesStore) Services() storage.ServiceRepository {
	return failingServiceRepo{ServiceRepository: f.Store.Services()}
}

type failingServiceRepo struct {
	storage.ServiceRepository
}

func (failingServiceRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Service, error) {
	return nil, fmt.Errorf("simulated storage failure (test fixture)")
}

func buildOrchestratorAgainstFailingStore(t *testing.T, srv *httptest.Server) *Orchestrator {
	t.Helper()
	realStore, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { realStore.Close() })
	store := failingServicesStore{Store: realStore}

	host := srv.Listener.Addr().String()
	_, portStr, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{
		ID: "rule-1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            dns.New(2 * time.Second),
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{port},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		Logger:              discardTestLogger(),
	}

	return &Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       detection.NewRegistry(), // deliberately empty -- BuildTargets fails before the registry is even consulted
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 2, Timeout: 2 * time.Second},
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  discardTestLogger(),
		Limits:                  DefaultLimits(),
	}
}

// buildOrchestratorAgainstRealStore is buildOrchestratorAgainstFailingStore
// without the storage failure -- for exercising state B (crawler
// disabled, no eligible targets) and state A (crawler enabled) against
// a real, unmodified store.
func buildOrchestratorAgainstRealStore(t *testing.T, srv *httptest.Server, crawlEnabled bool) *Orchestrator {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{
		ID: "rule-1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            dns.New(2 * time.Second),
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{port},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        crawlEnabled,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       10,
		Logger:              discardTestLogger(),
	}

	reg := detection.NewRegistry()
	if err := reg.Register(xssreflectedDetectorForTest{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	return &Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       reg,
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 2, Timeout: 2 * time.Second},
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  discardTestLogger(),
		Limits:                  DefaultLimits(),
	}
}

func TestDetectionState_NotRun_WhenCrawlerDisabled_WarningMentionsCrawler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/search?q=hello">search</a></body></html>`))
	}))
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false) // crawler disabled
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v (status=%s errors=%+v)", err, result.Status, result.Errors)
	}

	if result.DetectorSummary.State != DetectionStateNotRun {
		t.Errorf("DetectionState = %s, want NOT_RUN", result.DetectorSummary.State)
	}
	if result.DetectorSummary.EligibleTargets != 0 {
		t.Errorf("EligibleTargets = %d, want 0 (crawler disabled -> no endpoint targets)", result.DetectorSummary.EligibleTargets)
	}
	if result.DetectorSummary.DetectorRuns != 0 {
		t.Errorf("DetectorRuns = %d, want 0", result.DetectorSummary.DetectorRuns)
	}
	if result.DetectorSummary.DetectorsRegistered != 1 || result.DetectorSummary.DetectorsEnabled != 1 {
		t.Errorf("DetectorsRegistered/Enabled = %d/%d, want 1/1", result.DetectorSummary.DetectorsRegistered, result.DetectorSummary.DetectorsEnabled)
	}
	if result.Status != StatusCompletedWithWarnings {
		t.Errorf("Status = %s, want COMPLETED_WITH_WARNINGS", result.Status)
	}

	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "crawling is disabled") && strings.Contains(w, "DETECTION_NOT_RUN") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("no warning mentioning crawler-disabled found; Warnings = %+v", result.Warnings)
	}
}

// xssreflectedDetectorForTest avoids importing internal/detectors/xssreflected
// directly (a small, deliberate dependency-direction choice: this
// package's tests should not need to know about a specific real
// detector's package just to prove eligibility/warning wiring works --
// a minimal stand-in with the exact same Eligible() shape is enough).
type xssreflectedDetectorForTest struct{}

func (xssreflectedDetectorForTest) Metadata() detection.Metadata {
	return detection.Metadata{
		ID: "test-xss-stand-in", Name: "Test XSS Stand-in", Category: "test",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{http.MethodGet},
		DefaultSeverity:      models.SeverityMedium,
	}
}
func (xssreflectedDetectorForTest) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint && t.Method == http.MethodGet && t.Parameter != "" && t.ParameterLocation == "query"
}
func (xssreflectedDetectorForTest) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
}

func TestDetectionState_Failed_WhenBuildTargetsHardErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>benign</body></html>"))
	}))
	defer srv.Close()

	orch := buildOrchestratorAgainstFailingStore(t, srv)
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})

	if err == nil {
		t.Fatal("Run succeeded despite a forced storage failure inside the detection stage, want an error")
	}
	if result.Status != StatusFailed {
		t.Errorf("Status = %s, want FAILED", result.Status)
	}
	if result.DetectorSummary.State != DetectionStateFailed {
		t.Errorf("DetectionState = %s, want FAILED (state C: eligible-or-not, the stage itself did not complete)", result.DetectorSummary.State)
	}
	// State C must never be confused with state B: DetectorRuns == 0 is
	// true here too, but for a completely different reason (a hard
	// error, not "nothing was eligible") -- State is what disambiguates
	// them, not DetectorRuns alone.
	if result.DetectorSummary.DetectorRuns != 0 {
		t.Errorf("DetectorRuns = %d, want 0", result.DetectorSummary.DetectorRuns)
	}
	foundStageError := false
	for _, e := range result.Errors {
		if e.Category == ErrorCategoryStage && e.Stage == StageDetection {
			foundStageError = true
		}
	}
	if !foundStageError {
		t.Errorf("no ErrorCategoryStage error recorded for StageDetection; Errors = %+v", result.Errors)
	}
}
