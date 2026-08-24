// Phase 3.30 Finding Correlation & Vulnerability Chain Foundation:
// proves internal/chains against REAL models.Finding values produced
// through the existing, unmodified detector pipeline -- no new
// vulnerable fixtures are added for this phase (task's own "use the
// existing lab infrastructure... do not create unnecessary new
// vulnerable fixtures"). The POSITIVE data-flow/precondition
// correlation scenarios (info exposure -> object identifier,
// redirect -> endpoint, SSRF -> internal resource) are proven with
// synthetic-but-realistic Finding/Evidence values directly in
// internal/chains' own unit tests (per the task's own explicit "do
// NOT implement the actual vulnerability detectors for these
// scenarios" instruction) -- this file's own job is narrower: prove
// the engine behaves correctly, and safely, against REAL findings and
// REAL scan/identity boundaries.
package lab

import (
	"context"
	"testing"

	"sakanner/internal/chains"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjectionactive"
	"sakanner/internal/detectors/sqliactive"
	"sakanner/internal/detectors/sstiactive"
	"sakanner/internal/detectors/xssactive"
	"sakanner/internal/orchestrator"
	"sakanner/pkg/models"
)

func realActiveRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	for _, d := range []detection.Detector{sqliactive.New(), xssactive.New(), cmdinjectionactive.New(), sstiactive.New()} {
		if err := r.Register(d); err != nil {
			t.Fatalf("Register(%s): %v", d.Metadata().ID, err)
		}
	}
	return r
}

// TestPhase3_30_RealFindings_StructuralRelationsAndTraceability runs
// a REAL scan against the REAL lab, feeds the REAL resulting findings
// into chains.Correlate, and proves every relation/candidate remains
// fully traceable back to real, persisted finding IDs, never crosses
// the one real ScanJobID this scan produced, and never panics or
// misbehaves against real (not hand-crafted) evidence content.
func TestPhase3_30_RealFindings_StructuralRelationsAndTraceability(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: realActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 real findings from a broad detector run against the lab to make this test meaningful, got %d", len(findings))
	}

	res := chains.Correlate(findings, chains.DefaultLimits())

	findingByID := map[string]bool{}
	for _, f := range findings {
		findingByID[f.ID] = true
	}
	for _, r := range res.Relations {
		if !findingByID[r.FindingAID] || !findingByID[r.FindingBID] {
			t.Errorf("relation references a finding ID not present in the real findings set: %+v", r)
		}
		if r.ScanJobID != job.ID {
			t.Errorf("relation ScanJobID = %q, want %q (the real scan's own job ID)", r.ScanJobID, job.ID)
		}
	}
	for _, c := range res.Candidates {
		if c.ScanJobID != job.ID {
			t.Errorf("candidate ScanJobID = %q, want %q", c.ScanJobID, job.ID)
		}
		for _, fid := range c.FindingIDs {
			if !findingByID[fid] {
				t.Errorf("candidate references a finding ID not present in the real findings set: %+v", c)
			}
		}
		for _, rid := range c.RelationIDs {
			found := false
			for _, r := range res.Relations {
				if r.ID == rid {
					found = true
				}
			}
			if !found {
				t.Errorf("candidate references RelationID %q not present in res.Relations", rid)
			}
		}
	}
}

// TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation runs TWO
// real, independent authenticated scans (Phase 3.16's own two real
// accounts), each producing real findings under its own real
// IdentityContext, merges both real finding sets into ONE
// chains.Correlate call, and proves no relation or chain candidate
// ever spans both identities -- the task's own worked example, now
// proven against real, not synthetic, authenticated findings.
func TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation(t *testing.T) {
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
		t.Fatalf("expected real findings from both authenticated scans, got %d (account-a) and %d (account-b)", len(findingsA), len(findingsB))
	}

	merged := append(append([]models.Finding{}, findingsA...), findingsB...)
	res := chains.Correlate(merged, chains.DefaultLimits())

	for _, r := range res.Relations {
		t.Errorf("SECURITY: found a relation between the two independently-authenticated real scans' own findings -- must be zero: %+v", r)
	}
	for _, c := range res.Candidates {
		t.Errorf("SECURITY: found a chain candidate spanning two real, independently-authenticated identities: %+v", c)
	}
}
