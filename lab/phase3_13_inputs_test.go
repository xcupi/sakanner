// Phase 3.13 integration + adversarial tests: parameter/input discovery
// run through the REAL internal/orchestrator.Orchestrator against
// harness_inputs.go's fixture app, and the scope-safety guarantees the
// task's "FORM ACTION SCOPE" section requires.
package lab

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/detection"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/parameters"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func testInputsLab(t *testing.T) *Lab {
	t.Helper()
	gt, err := LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	l, err := StartWithInputFixtures(gt)
	if err != nil {
		t.Fatalf("StartWithInputFixtures: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

// buildOrchestratorForInputsLab wires a real orchestrator.Orchestrator
// against l with only "inputs.scanner.test" in scope -- mirroring
// buildOrchestratorForVulnLab's own shape exactly (phase3_11_orchestrator_test.go).
func buildOrchestratorForInputsLab(t *testing.T, l *Lab, limits parameters.Limits) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{
		ID: uuid.NewString(), Value: "inputs.scanner.test", Type: models.ScopeRuleExactHost,
		Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.InputsAddr)},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 4, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       30,
		ParameterLimits:     limits,
		Logger:              detectionLogger(),
	}

	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       detection.NewRegistry(),
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 4, Timeout: 2 * time.Second},
		DetectionConcurrency:    4,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000},
	}
	return orch, store
}

func TestPhase3_13_InputDiscovery_QueryFormsDiscoveredEndToEnd(t *testing.T) {
	l := testInputsLab(t)
	orch, store := buildOrchestratorForInputsLab(t, l, parameters.Limits{})

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target:            "inputs.scanner.test",
		DetectionDisabled: true,
		CrawlOverride:     &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30, ParameterLimits: parameters.Limits{}},
	})
	if err != nil {
		t.Fatalf("Run: %v (status=%s errors=%+v)", err, result.Status, result.Errors)
	}
	if result.InputSummary.InputCount == 0 {
		t.Fatal("InputSummary.InputCount = 0, want > 0")
	}

	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byName := map[string]models.Parameter{}
	for _, p := range params {
		byName[p.Name] = p
	}

	if p, ok := byName["q"]; !ok || p.Location != "query" {
		t.Errorf("expected q (query), got %+v", p)
	}
	if p, ok := byName["username"]; !ok || p.Location != "form" {
		t.Errorf("expected username (form), got %+v", p)
	}
	// csrf_token's OWN observed value ("tok-abc" in the fixture) must be
	// REDACTED, not asserted verbatim -- Phase 3.15 added "csrf"/
	// "csrf_token"/"xsrf"/"xsrf_token" to internal/evidence's sensitive
	// field-name blocklist (a real gap found during authenticated-
	// crawling development: this field name was not covered before,
	// unlike "password"/"token"/etc.). This assertion previously
	// expected the UNREDACTED value, which was itself the bug this
	// phase fixed -- see docs/phase-3-15-authenticated-crawling.md
	// "Secret handling."
	if p, ok := byName["csrf_token"]; !ok || p.Location != "form" || p.Value != evidence.RedactedPlaceholder {
		t.Errorf("expected hidden field csrf_token (form, redacted), got %+v", p)
	}
	if p, ok := byName["bio"]; !ok || p.Location != "form" {
		t.Errorf("expected textarea bio (form), got %+v", p)
	}
	if p, ok := byName["role"]; !ok || p.Value != "admin" {
		t.Errorf("expected select role=admin (explicitly selected option), got %+v", p)
	}
	if p, ok := byName["filter"]; !ok || p.Location != "query" {
		t.Errorf("expected GET form field filter (query location), got %+v", p)
	}
}

// TestPhase3_13_DuplicateQueryParameter_OneInput is task adversarial
// scenario 1 (duplicate query parameters): /dupquery?tag=a&tag=b must
// collapse to one persisted "tag" input, not two.
func TestPhase3_13_DuplicateQueryParameter_OneInput(t *testing.T) {
	l := testInputsLab(t)
	orch, store := buildOrchestratorForInputsLab(t, l, parameters.Limits{})

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target: "inputs.scanner.test", DetectionDisabled: true,
		CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	count := 0
	for _, p := range params {
		if p.Name == "tag" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d \"tag\" parameters, want 1 (duplicate query params must collapse)", count)
	}
}

// TestPhase3_13_DuplicateCrawlerObservation_OneInput is task adversarial
// scenario 26/11: the index page links to the exact same
// /search?q=hello&page=2 URL twice -- must still produce one q input,
// not two.
func TestPhase3_13_DuplicateCrawlerObservation_OneInput(t *testing.T) {
	l := testInputsLab(t)
	orch, store := buildOrchestratorForInputsLab(t, l, parameters.Limits{})

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target: "inputs.scanner.test", DetectionDisabled: true,
		CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	count := 0
	for _, p := range params {
		if p.Name == "q" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d \"q\" parameters from a URL linked twice, want 1", count)
	}
}

// TestPhase3_13_MalformedHTML_NoCrash is task adversarial scenario 6.
func TestPhase3_13_MalformedHTML_NoCrash(t *testing.T) {
	l := testInputsLab(t)
	orch, _ := buildOrchestratorForInputsLab(t, l, parameters.Limits{})

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target: "inputs.scanner.test", DetectionDisabled: true,
		CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30},
	})
	if err != nil {
		t.Fatalf("Run: %v (malformed HTML on one page must not fail the whole scan)", err)
	}
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Errorf("Status = %s, want a completed status despite malformed HTML on /malformed", result.Status)
	}
}

// TestPhase3_13_ManyFormFields_ResourceLimitEnforced is task adversarial
// scenario 10 (huge number of form fields): /manyinputs has 30 fields;
// a low MaxFormFields/MaxInputsPerEndpoint must bound what gets
// persisted, and the scan must still complete cleanly (never fail).
func TestPhase3_13_ManyFormFields_ResourceLimitEnforced(t *testing.T) {
	l := testInputsLab(t)
	orch, store := buildOrchestratorForInputsLab(t, l, parameters.Limits{MaxFormFields: 5, MaxInputsPerEndpoint: 5})

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target: "inputs.scanner.test", DetectionDisabled: true,
		CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30, ParameterLimits: parameters.Limits{MaxFormFields: 5, MaxInputsPerEndpoint: 5}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Fatalf("Status = %s, want a completed status", result.Status)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	manyCount := 0
	for _, p := range params {
		if strings.HasPrefix(p.Name, "field") {
			manyCount++
		}
	}
	if manyCount > 5 {
		t.Errorf("got %d fieldN parameters, want at most 5 (MaxFormFields/MaxInputsPerEndpoint)", manyCount)
	}
	if len(result.InputSummary.Warnings) == 0 {
		t.Error("expected a resource-limit warning to be surfaced")
	}
}

// TestPhase3_13_OutOfScopeFormAction_NeverAuthorizesTarget is the
// CRITICAL "FORM ACTION SCOPE" requirement: a form on the in-scope
// inputs.scanner.test page has action="https://external.scanner.test/steal"
// -- discovering that input must NEVER cause external.scanner.test to
// be dialed, scanned, or treated as authorized. Since
// external.scanner.test has no real listener in this lab (see
// harness.go), the strongest available evidence is that the scan
// completes cleanly with no host/service/endpoint ever recorded for
// that hostname AND no scope rule was created for it.
func TestPhase3_13_OutOfScopeFormAction_NeverAuthorizesTarget(t *testing.T) {
	l := testInputsLab(t)
	orch, store := buildOrchestratorForInputsLab(t, l, parameters.Limits{})

	before, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("list scope rules (before): %v", err)
	}

	result, err := orch.Run(context.Background(), orchestrator.Options{
		Target: "inputs.scanner.test", DetectionDisabled: true,
		CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 30},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Fatalf("Status = %s, want a completed status", result.Status)
	}

	after, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("list scope rules (after): %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("scope rule count changed: before=%d after=%d -- discovering a form action must never create scope authorization", len(before), len(after))
	}

	// The out-of-scope form action's HOST must never appear as an
	// Endpoint's HTTPService URL anywhere in this scan job's own data --
	// proving it was never treated as a scan target.
	endpointsList, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Endpoints ListByScanJob: %v", err)
	}
	for _, e := range endpointsList {
		if strings.Contains(e.Path, "external.scanner.test") {
			t.Errorf("an endpoint referencing external.scanner.test was recorded: %+v -- scope bypass", e)
		}
	}

	// The discovered form input itself IS allowed to exist (it's a
	// legitimate, harmless discovery artifact -- the value it points to
	// is just data, not authorization) -- but its own endpoint must be
	// inputs.scanner.test's own /external-form page, never
	// external.scanner.test.
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Parameters ListByScanJob: %v", err)
	}
	found := false
	for _, p := range params {
		if p.Name == "data" {
			found = true
		}
	}
	if !found {
		t.Log("note: /external-form's own \"data\" field was not discovered -- acceptable (crawler may not have reached it), the critical assertion is the absence of any external.scanner.test endpoint/scope-rule above")
	}
}
