// Phase 3.31 Vulnerability Chain Integration, Persistence & Reporting
// Foundation: proves internal/orchestrator's own new chain-correlation
// step (added this phase, right after Phase 3.8's existing dedup
// stage) against the REAL detector pipeline, REAL persistence, and
// REAL multi-identity/scope isolation. No new vulnerable fixtures are
// added for this phase (task's own "do not create unnecessary new
// vulnerable fixtures") -- the existing broad detector set already
// reliably produces genuine, independently-discovered, related
// findings against the existing lab.
package lab

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/chains"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjectionactive"
	"sakanner/internal/detectors/sqliactive"
	"sakanner/internal/detectors/sstiactive"
	"sakanner/internal/detectors/xssactive"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func broadChainsRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	for _, d := range []detection.Detector{sqliactive.New(), xssactive.New(), cmdinjectionactive.New(), sstiactive.New()} {
		if err := r.Register(d); err != nil {
			t.Fatalf("Register(%s): %v", d.Metadata().ID, err)
		}
	}
	return r
}

// vulnOrchestrator builds a real, unauthenticated Orchestrator against
// vuln.scanner.test, backed by store (caller-supplied so tests can
// reuse a file-based store across a "close and reopen" reload check).
func vulnOrchestrator(t *testing.T, l *Lab, store storage.Store) *orchestrator.Orchestrator {
	t.Helper()
	rules := []models.ScopeRule{{ID: "r1", Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}}
	for _, r := range rules {
		if err := store.ScopeRules().Create(context.Background(), r); err != nil {
			t.Fatalf("create scope rule: %v", err)
		}
	}
	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.VulnAddr)},
		PortDialTimeout:     500 * time.Millisecond,
		HTTPConfig:          httpstage.Config{Timeout: 3 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 4, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       6,
		CrawlMaxPages:       100,
		Logger:              detectionLogger(),
	}
	return &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       broadChainsRegistry(t),
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 8, Timeout: 3 * time.Second},
		DetectionConcurrency:    8,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 30 * time.Second},
	}
}

// ---------------------------------------------------------------------
// GENUINE CHAIN: real scan -> real findings -> real persisted chains
// ---------------------------------------------------------------------

func TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain(t *testing.T) {
	l := testVulnLab(t)
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	orch := vulnOrchestrator(t, l, store)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 real, independently-discovered findings to make this test meaningful, got %d", len(findings))
	}

	// Individual findings remain independently, unconditionally
	// visible regardless of chain participation -- task section 3's
	// own "a vulnerability must remain independently visible even
	// when it participates in a chain."
	for _, f := range findings {
		if f.ID == "" || f.VulnerabilityType == "" {
			t.Errorf("finding missing required fields: %+v", f)
		}
	}

	relations, err := store.Chains().Relations(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Chains().Relations: %v", err)
	}
	candidates, err := store.Chains().Candidates(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Chains().Candidates: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("expected at least one genuine chain candidate to have been persisted from this real, broad scan")
	}
	t.Logf("real scan produced %d findings, %d relations, %d chain candidates", len(findings), len(relations), len(candidates))

	// Every persisted candidate must be fully traceable.
	findingByID := map[string]bool{}
	for _, f := range findings {
		findingByID[f.ID] = true
	}
	relByID := map[string]bool{}
	for _, r := range relations {
		relByID[r.ID] = true
		if !findingByID[r.FindingAID] || !findingByID[r.FindingBID] {
			t.Errorf("persisted relation references an unknown finding: %+v", r)
		}
		if r.ScanJobID != result.ScanID {
			t.Errorf("persisted relation ScanJobID = %q, want %q", r.ScanJobID, result.ScanID)
		}
	}
	for _, c := range candidates {
		if c.ScanJobID != result.ScanID {
			t.Errorf("persisted candidate ScanJobID = %q, want %q", c.ScanJobID, result.ScanID)
		}
		if c.Status == chains.ChainConfirmed {
			t.Errorf("SECURITY: a real scan produced a CONFIRMED chain -- this phase's own policy must never assign it automatically: %+v", c)
		}
		for _, fid := range c.FindingIDs {
			if !findingByID[fid] {
				t.Errorf("persisted candidate references an unknown finding: %+v", c)
			}
		}
		for _, rid := range c.RelationIDs {
			if !relByID[rid] {
				t.Errorf("persisted candidate references an unknown relation: %+v", c)
			}
		}
	}

	// Detection genuinely continued testing every eligible target
	// after finding vulnerabilities -- task section 3's own "the
	// scanner must continue testing all eligible inputs and all
	// eligible detectors after finding one vulnerability." Multiple
	// DISTINCT detector IDs among the real findings is direct evidence
	// detection did not stop early.
	detectorIDs := map[string]bool{}
	for _, f := range findings {
		detectorIDs[f.DetectorID] = true
	}
	if len(detectorIDs) < 2 {
		t.Errorf("expected findings from at least 2 distinct detectors (proving detection continued across detectors), got: %v", detectorIDs)
	}
}

// ---------------------------------------------------------------------
// DATABASE RELOAD: chains survive close + reopen
// ---------------------------------------------------------------------

func TestPhase3_31_DatabaseReload_ReproducesSameChains(t *testing.T) {
	l := testVulnLab(t)
	dbPath := t.TempDir() + "/reload-test.db"

	store1, err := sqlite.New(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("sqlite.New (1st open): %v", err)
	}
	orch := vulnOrchestrator(t, l, store1)
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	relationsBefore, err := store1.Chains().Relations(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Relations (before close): %v", err)
	}
	candidatesBefore, err := store1.Chains().Candidates(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Candidates (before close): %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := sqlite.New(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("sqlite.New (2nd open, reload): %v", err)
	}
	defer store2.Close()
	relationsAfter, err := store2.Chains().Relations(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Relations (after reload): %v", err)
	}
	candidatesAfter, err := store2.Chains().Candidates(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("Candidates (after reload): %v", err)
	}

	if len(relationsAfter) != len(relationsBefore) {
		t.Fatalf("relation count changed across reload: before=%d after=%d", len(relationsBefore), len(relationsAfter))
	}
	for i := range relationsBefore {
		if relationsBefore[i].ID != relationsAfter[i].ID || relationsBefore[i].Type != relationsAfter[i].Type {
			t.Errorf("relation %d differs across reload: before=%+v after=%+v", i, relationsBefore[i], relationsAfter[i])
		}
	}
	if len(candidatesAfter) != len(candidatesBefore) {
		t.Fatalf("candidate count changed across reload: before=%d after=%d", len(candidatesBefore), len(candidatesAfter))
	}
	for i := range candidatesBefore {
		if candidatesBefore[i].ID != candidatesAfter[i].ID || candidatesBefore[i].Status != candidatesAfter[i].Status {
			t.Errorf("candidate %d differs across reload: before=%+v after=%+v", i, candidatesBefore[i], candidatesAfter[i])
		}
	}
}

// ---------------------------------------------------------------------
// IDENTITY ISOLATION at the persisted, real-orchestrator level
// ---------------------------------------------------------------------

// TestPhase3_31_TaskWorkedExample_RealPersistedFindings reproduces the
// task's own literal worked example (Account A IDOR + Account B XSS on
// the same object must never chain) using REAL findings produced by a
// REAL orchestrator run and READ BACK from REAL persistence.
func TestPhase3_31_TaskWorkedExample_RealPersistedFindings(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	orchA, storeA := deepAuthSSTIOrchestrator(t, l, rules)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run (account-a): %v", err)
	}
	findingsA, err := storeA.Findings().ListByScanJob(context.Background(), resultA.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob (account-a): %v", err)
	}

	orchB, storeB := deepAuthSSTIOrchestrator(t, l, rules)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run (account-b): %v", err)
	}
	findingsB, err := storeB.Findings().ListByScanJob(context.Background(), resultB.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob (account-b): %v", err)
	}
	if len(findingsA) == 0 || len(findingsB) == 0 {
		t.Fatalf("expected real findings from both independently-authenticated scans, got %d (A) and %d (B)", len(findingsA), len(findingsB))
	}

	// Each scan's OWN persisted chains must never reference the OTHER
	// scan's findings (they were computed and saved independently,
	// against independent ScanJobIDs).
	relA, err := storeA.Chains().Relations(context.Background(), resultA.ScanID)
	if err != nil {
		t.Fatalf("Relations (account-a): %v", err)
	}
	idsB := map[string]bool{}
	for _, f := range findingsB {
		idsB[f.ID] = true
	}
	for _, r := range relA {
		if idsB[r.FindingAID] || idsB[r.FindingBID] {
			t.Errorf("SECURITY: account-a's own persisted relation references an account-b finding: %+v", r)
		}
	}

	// Direct reproduction of the task's own worked example using a
	// MERGED set of the two real, independently-produced finding
	// lists (mirroring what a hypothetical single cross-scan
	// correlation call would see) -- must produce zero relations
	// between them.
	merged := append(append([]models.Finding{}, findingsA...), findingsB...)
	res := chains.Correlate(merged, chains.DefaultLimits())
	for _, r := range res.Relations {
		aIsA, bIsA := false, false
		for _, f := range findingsA {
			if r.FindingAID == f.ID {
				aIsA = true
			}
			if r.FindingBID == f.ID {
				bIsA = true
			}
		}
		if aIsA != bIsA {
			// One side belongs to account-a's own findings and the
			// other does not -- meaning it crossed into account-b's.
			t.Errorf("SECURITY: a relation crossed the two independently-authenticated identities' own findings: %+v", r)
		}
	}
}

// ---------------------------------------------------------------------
// SCOPE ISOLATION
// ---------------------------------------------------------------------

// TestPhase3_31_ScopeIsolation_OutOfScopeCandidateNeverReachable proves
// an out-of-scope host's own (synthetic, since a real scan would never
// produce one) finding never gets treated as "reachable" or related to
// an in-scope finding merely by being fed into the SAME Correlate
// call -- chain correlation must never weaken scope enforcement, which
// happens entirely upstream (a Finding only exists because a detector
// already ran against an in-scope target); this test proves chain
// correlation does not ITSELF introduce a bypass if that invariant
// were ever violated upstream.
func TestPhase3_31_ScopeIsolation_OutOfScopeCandidateNeverReachable(t *testing.T) {
	inScope := newFindingForScopeTest("f1", "scan1", "sqli", "vuln.scanner.test", 80, "/sqli/vulnerable", "id", "http://vuln.scanner.test/sqli/vulnerable?id=OBJ-5591")
	outOfScope := newFindingForScopeTest("f2", "scan1", "idor", "external.scanner.test", 80, "/objects", "id", "http://external.scanner.test/objects?id=OBJ-5591")
	res := chains.Correlate([]models.Finding{inScope, outOfScope}, chains.DefaultLimits())
	for _, r := range res.Relations {
		if r.Type == chains.RelationSameEndpoint {
			t.Error("SECURITY: an in-scope and an out-of-scope host were treated as SAME_ENDPOINT")
		}
	}
	for _, c := range res.Candidates {
		if c.Status == chains.ChainSupported || c.Status == chains.ChainConfirmed {
			t.Errorf("SECURITY: an out-of-scope-host-involving pairing reached %s status: %+v", c.Status, c)
		}
	}
}

func newFindingForScopeTest(id, scanID, vulnType, host string, port int, endpoint, param, url string) models.Finding {
	return models.Finding{
		ID: id, ScanID: scanID, VulnerabilityType: vulnType, Host: host, Port: port,
		AffectedEndpoint: endpoint, AffectedParameter: param, URL: url,
		Severity: models.SeverityMedium, Confidence: 0.8, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------
// CONCURRENT SCANS
// ---------------------------------------------------------------------

func TestPhase3_31_ConcurrentScans_IndependentPersistedChains(t *testing.T) {
	l := testVulnLab(t)
	const n = 3
	type outcome struct {
		scanID     string
		candidates int
	}
	results := make(chan outcome, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			store, err := sqlite.New(context.Background(), ":memory:")
			if err != nil {
				errs <- err
				return
			}
			defer store.Close()
			orch := vulnOrchestrator(t, l, store)
			result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
			if err != nil {
				errs <- err
				return
			}
			candidates, err := store.Chains().Candidates(context.Background(), result.ScanID)
			if err != nil {
				errs <- err
				return
			}
			results <- outcome{scanID: result.ScanID, candidates: len(candidates)}
		}()
	}
	scanIDs := map[string]bool{}
	for i := 0; i < n; i++ {
		select {
		case err := <-errs:
			t.Fatalf("concurrent scan failed: %v", err)
		case o := <-results:
			if scanIDs[o.scanID] {
				t.Errorf("SECURITY: two concurrent scans produced the SAME ScanJobID: %s", o.scanID)
			}
			scanIDs[o.scanID] = true
		}
	}
}

// ---------------------------------------------------------------------
// CHAIN PERSISTENCE FAILURE ISOLATION
// ---------------------------------------------------------------------

// errorChainsStore wraps a real storage.Store, overriding ONLY
// Chains() to always fail -- Go's interface embedding forwards every
// OTHER method to the real store unchanged, so this is a minimal,
// targeted failure injection without reimplementing the whole
// storage.Store surface.
type errorChainsStore struct{ storage.Store }

func (s errorChainsStore) Chains() storage.ChainRepository { return errorChainRepo{} }

type errorChainRepo struct{}

func (errorChainRepo) SaveResult(ctx context.Context, scanJobID string, result chains.Result) error {
	return errors.New("injected failure: chain persistence unavailable")
}
func (errorChainRepo) Relations(ctx context.Context, scanJobID string) ([]chains.FindingRelation, error) {
	return nil, errors.New("injected failure")
}
func (errorChainRepo) Candidates(ctx context.Context, scanJobID string) ([]chains.ChainCandidate, error) {
	return nil, errors.New("injected failure")
}

// TestPhase3_31_ChainPersistenceFailure_NeverFailsTheScan proves task
// section 3's own "do NOT allow chain correlation to interfere with
// individual finding generation": a chain-persistence failure is
// isolated (a warning, not a stage failure), and every individual
// finding remains available regardless.
func TestPhase3_31_ChainPersistenceFailure_NeverFailsTheScan(t *testing.T) {
	l := testVulnLab(t)
	realStore, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { realStore.Close() })
	wrapped := errorChainsStore{Store: realStore}

	orch := vulnOrchestrator(t, l, wrapped)
	orch.Store = wrapped // ensure the orchestrator's OWN field uses the wrapped store

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v (a chain-persistence failure must never fail the whole scan)", err)
	}
	findings, err := realStore.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings to still be persisted and readable despite the chain-persistence failure")
	}
}
