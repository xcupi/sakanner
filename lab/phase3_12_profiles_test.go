// Phase 3.12 adversarial tests: profiles must never bypass, weaken, or
// otherwise influence scope enforcement -- task's explicit "NO SCOPE
// BYPASS" requirement across every adversarial scenario. These tests
// run the REAL internal/orchestrator.Orchestrator (not a stub) with
// Options fields shaped exactly the way cmd/scanner's own profile
// resolution would set them for "recon"/"web"/"deep" (DetectionDisabled,
// CrawlOverride) against the real lab's existing out-of-scope fixtures
// -- reusing lab's established scope-adversarial fixtures
// (external.scanner.test, admin.scanner.test's CNAME-to-out-of-scope-IP)
// rather than adding new ones, since these already exercise exactly
// the scenarios task's adversarial list names.
package lab

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// profileStyleOptions mirrors exactly what cmd/scanner's profile
// resolution (internal/policy.Resolve, translated in
// cmd/scanner/scan.go's runFullScan) sets on Options for each built-in
// profile -- reproduced here rather than importing internal/policy, to
// keep this adversarial suite testing the ORCHESTRATOR's own
// enforcement (which must hold regardless of what set these fields),
// not the policy package's translation itself (already covered by
// internal/policy's and internal/orchestrator's own unit tests).
func profileStyleOptions(target string) map[string]orchestrator.Options {
	return map[string]orchestrator.Options{
		"recon": {Target: target, ProfileLabel: "recon", DetectionDisabled: true, CrawlOverride: &orchestrator.CrawlSettings{Enabled: false}},
		"web":   {Target: target, ProfileLabel: "web", CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 20}},
		"deep":  {Target: target, ProfileLabel: "deep", CrawlOverride: &orchestrator.CrawlSettings{Enabled: true, MaxDepth: 4, MaxPages: 75}},
	}
}

// buildScopeAdversarialOrchestrator wires a real Orchestrator against
// the plain (non-vuln) lab l, with exactly the given scope rules --
// letting each test control precisely what is and is not authorized.
func buildScopeAdversarialOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	for _, r := range rules {
		if r.ID == "" {
			r.ID = uuid.NewString()
		}
		if r.CreatedAt.IsZero() {
			r.CreatedAt = time.Now().UTC()
		}
		if err := store.ScopeRules().Create(context.Background(), r); err != nil {
			t.Fatalf("create scope rule %+v: %v", r, err)
		}
	}

	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{80, 443},
		PortDialTimeout:     500 * time.Millisecond,
		HTTPConfig:          httpstage.Config{Timeout: 1 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		Logger:              detectionLogger(),
	}
	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       registerBenignDetectors(t),
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 2, Timeout: 1 * time.Second},
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 5 * time.Second},
	}
	return orch, store
}

// TestPhase3_12_OutOfScopeTarget_AllProfileStyles_NoBypass is task
// adversarial scenario 1/12/13 combined: an out-of-scope target must
// fail at SCOPE identically under recon-, web-, and deep-style
// Options -- proving profile choice has zero influence on scope
// enforcement, and that a more "active" profile (web/deep) cannot
// enable a target recon's own inert settings would have refused too.
func TestPhase3_12_OutOfScopeTarget_AllProfileStyles_NoBypass(t *testing.T) {
	l := testLab(t)
	// Only redirect.scanner.test is authorized -- external.scanner.test
	// has no rule at all, matching the existing redirect_test.go
	// convention for "deliberately absent, not coincidentally absent."
	orch, store := buildScopeAdversarialOrchestrator(t, l, []models.ScopeRule{
		{Value: "redirect.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow},
	})

	for name, opts := range profileStyleOptions("external.scanner.test") {
		t.Run(name, func(t *testing.T) {
			result, err := orch.Run(context.Background(), opts)
			if err == nil {
				t.Fatal("Run succeeded against an out-of-scope target, want a scope error regardless of profile")
			}
			if result.Status != orchestrator.StatusFailed {
				t.Errorf("Status = %s, want FAILED", result.Status)
			}
			foundScopeError := false
			for _, e := range result.Errors {
				if strings.Contains(strings.ToLower(e.Message), "scope") {
					foundScopeError = true
				}
			}
			if !foundScopeError {
				t.Errorf("no scope-related error recorded: %+v", result.Errors)
			}
			if result.ReconSummary.HostCount != 0 || result.ReconSummary.HTTPServiceCount != 0 {
				t.Errorf("recon summary shows activity (%+v) against an out-of-scope target -- recon must never have started", result.ReconSummary)
			}
			if result.DetectorSummary.DetectorRuns != 0 {
				t.Errorf("DetectorRuns = %d, want 0 -- detection must never run against an out-of-scope target under any profile", result.DetectorSummary.DetectorRuns)
			}
		})
	}
	_ = store
}

// TestPhase3_12_ScopeRulesNeverModified_AnyProfileStyle is task's
// "profiles MUST NOT modify scope rules" requirement, checked directly
// -- before/after every profile-style Options combination against both
// an in-scope and an out-of-scope target, the scope_rules table must
// be byte-for-byte the same set of rules it started with.
func TestPhase3_12_ScopeRulesNeverModified_AnyProfileStyle(t *testing.T) {
	l := testLab(t)
	orch, store := buildScopeAdversarialOrchestrator(t, l, []models.ScopeRule{
		{Value: "redirect.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow},
	})

	before, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("list scope rules (before): %v", err)
	}

	for _, target := range []string{"redirect.scanner.test", "external.scanner.test", "admin.scanner.test"} {
		for name, opts := range profileStyleOptions(target) {
			opts := opts
			t.Run(target+"/"+name, func(t *testing.T) {
				_, _ = orch.Run(context.Background(), opts) // result irrelevant; only scope-table stability matters here
			})
		}
	}

	after, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("list scope rules (after): %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("scope rule count changed: before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i].ID != after[i].ID || before[i].Value != after[i].Value || before[i].Action != after[i].Action {
			t.Errorf("scope rule %d changed: before=%+v after=%+v", i, before[i], after[i])
		}
	}
}

// TestPhase3_12_SubdomainResolvingOutOfScope_AllProfileStyles is task
// adversarial scenarios 3/4 (DNS response pointing outside scope /
// subdomain confusion): admin.scanner.test's own hostname is
// authorized, but it CNAMEs to ipExternal -- an address with no scope
// rule of its own and nothing listening on it (see harness.go). Under
// every profile style, the scan must never report a live, reachable
// service on that resolved address -- a hostname-level "allow" must
// never be treated as authorizing whatever IP that name happens to
// resolve to, independent of which profile requested more aggressive
// crawling.
func TestPhase3_12_SubdomainResolvingOutOfScope_AllProfileStyles(t *testing.T) {
	l := testLab(t)
	orch, store := buildScopeAdversarialOrchestrator(t, l, []models.ScopeRule{
		{Value: "admin.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow},
	})

	for name, opts := range profileStyleOptions("admin.scanner.test") {
		t.Run(name, func(t *testing.T) {
			result, err := orch.Run(context.Background(), opts)
			// Either outcome (a clean error, or a COMPLETED scan that
			// simply found nothing because ipExternal refuses every
			// connection) is acceptable -- what is NOT acceptable is any
			// finding, HTTP service, or detector run attributed to this
			// target, since nothing legitimate could ever have been
			// observed there.
			_ = err
			if result.DetectorSummary.DetectorRuns != 0 {
				t.Errorf("DetectorRuns = %d, want 0 -- ipExternal has no real service to have produced this", result.DetectorSummary.DetectorRuns)
			}
			if len(result.Findings) != 0 {
				t.Errorf("Findings = %+v, want none", result.Findings)
			}
			if result.ReconSummary.HTTPServiceCount != 0 {
				t.Errorf("HTTPServiceCount = %d, want 0 -- ipExternal (RFC 5737 TEST-NET-3) has nothing listening", result.ReconSummary.HTTPServiceCount)
			}
		})
	}
	_ = store
}

// TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess is a static,
// structural check backing the above behavioral ones: task's "a
// profile cannot ... disable scope validation" is true not merely by
// current behavior but by CONSTRUCTION -- internal/policy imports
// nothing from internal/scope or internal/storage at all, so it is
// architecturally incapable of touching scope rules regardless of
// what any future profile definition might try to do. Mirrors
// internal/orchestrator/security_test.go's own AST-import-scan
// technique, pointed at ../internal/policy instead of "." -- lab/ is
// one level below the repo root (see docs/lab-isolation-review.md),
// so ".." reaches the root and "../internal/policy" reaches the
// package directly.
func TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess(t *testing.T) {
	forbidden := map[string]bool{
		"sakanner/internal/scope": true, "sakanner/internal/storage": true,
		"sakanner/internal/orchestration": true, "sakanner/internal/orchestrator": true,
	}
	dir := filepath.Join("..", "internal", "policy")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden[path] {
				t.Errorf("internal/policy/%s imports %q -- a profile-resolution package must have no access to scope, storage, or scan execution", name, path)
			}
		}
	}
}
