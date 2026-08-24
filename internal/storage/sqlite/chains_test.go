package sqlite

import (
	"context"
	"testing"
	"time"

	"sakanner/internal/chains"
	"sakanner/pkg/models"
)

func TestChains_SaveAndLoad_RoundTrips(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}

	result := chains.Result{
		Relations: []chains.FindingRelation{
			{
				ID: "rel1", Type: chains.RelationSameEndpoint, FindingAID: "f1", FindingBID: "f2",
				ScanJobID: "scan1", Reason: "same endpoint", Confidence: 0.6,
				Evidence: []chains.ChainEvidence{{Kind: chains.EvidenceSharedEndpoint, Description: "identical endpoint", Detail: "target.test:80/x"}},
			},
		},
		Candidates: []chains.ChainCandidate{
			{
				ID: "cand1", ScanJobID: "scan1", IdentityContext: "account-a",
				FindingIDs: []string{"f1", "f2"}, RelationIDs: []string{"rel1"},
				Endpoints: []string{"target.test:80/x"}, Status: chains.ChainPotential,
				Confidence: 0.6, ImpactEstimate: "2 findings", Reason: "connected via: SAME_ENDPOINT",
				MissingEvidence: []string{"evidence-level relation"},
			},
		},
	}

	if err := s.Chains().SaveResult(ctx, "scan1", result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 1 {
		t.Fatalf("expected 1 relation, got %d", len(relations))
	}
	got := relations[0]
	if got.ID != "rel1" || got.Type != chains.RelationSameEndpoint || got.FindingAID != "f1" || got.FindingBID != "f2" ||
		got.ScanJobID != "scan1" || got.Reason != "same endpoint" || got.Confidence != 0.6 {
		t.Errorf("relation round-trip mismatch: %+v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Detail != "target.test:80/x" {
		t.Errorf("relation evidence round-trip mismatch: %+v", got.Evidence)
	}

	candidates, err := s.Chains().Candidates(ctx, "scan1")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	gc := candidates[0]
	if gc.ID != "cand1" || gc.IdentityContext != "account-a" || gc.Status != chains.ChainPotential {
		t.Errorf("candidate round-trip mismatch: %+v", gc)
	}
	if len(gc.FindingIDs) != 2 || len(gc.RelationIDs) != 1 || len(gc.Endpoints) != 1 || len(gc.MissingEvidence) != 1 {
		t.Errorf("candidate slice-field round-trip mismatch: %+v", gc)
	}
}

func TestChains_SaveResult_ReplacesNotAppends(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}

	r1 := chains.Result{Relations: []chains.FindingRelation{{ID: "rel1", Type: chains.RelationSameEndpoint, FindingAID: "f1", FindingBID: "f2", ScanJobID: "scan1"}}}
	if err := s.Chains().SaveResult(ctx, "scan1", r1); err != nil {
		t.Fatalf("SaveResult (1st): %v", err)
	}
	// Save again with DIFFERENT content -- the old relation must be gone.
	r2 := chains.Result{Relations: []chains.FindingRelation{{ID: "rel2", Type: chains.RelationSameParameter, FindingAID: "f3", FindingBID: "f4", ScanJobID: "scan1"}}}
	if err := s.Chains().SaveResult(ctx, "scan1", r2); err != nil {
		t.Fatalf("SaveResult (2nd): %v", err)
	}

	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 1 || relations[0].ID != "rel2" {
		t.Errorf("expected exactly the 2nd save's own relation to survive, got: %+v", relations)
	}
}

func TestChains_SaveResult_IdempotentReplay(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	result := chains.Result{Relations: []chains.FindingRelation{{ID: "rel1", Type: chains.RelationSameEndpoint, FindingAID: "f1", FindingBID: "f2", ScanJobID: "scan1"}}}
	for i := 0; i < 3; i++ {
		if err := s.Chains().SaveResult(ctx, "scan1", result); err != nil {
			t.Fatalf("SaveResult (call %d): %v", i, err)
		}
	}
	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 1 {
		t.Fatalf("SaveResult called 3 times with identical input must leave exactly 1 relation, got %d", len(relations))
	}
}

func TestChains_EmptyResult_NoRowsPersisted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	if err := s.Chains().SaveResult(ctx, "scan1", chains.Result{}); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 0 {
		t.Errorf("expected zero relations for an empty Result, got %d", len(relations))
	}
	candidates, err := s.Chains().Candidates(ctx, "scan1")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(candidates) != 0 {
		t.Errorf("expected zero candidates for an empty Result, got %d", len(candidates))
	}
}

func TestChains_ScanJobDeletion_CascadesToChains(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	result := chains.Result{Relations: []chains.FindingRelation{{ID: "rel1", Type: chains.RelationSameEndpoint, FindingAID: "f1", FindingBID: "f2", ScanJobID: "scan1"}}}
	if err := s.Chains().SaveResult(ctx, "scan1", result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	if err := s.ScanJobs().Delete(ctx, "scan1"); err != nil {
		t.Fatalf("delete scan job: %v", err)
	}
	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 0 {
		t.Errorf("expected chain relations to be cascade-deleted with their scan job, got %d remaining", len(relations))
	}
}

// TestChains_StaleFindingReference_ReadsBackWithoutError proves a
// ChainCandidate/FindingRelation referencing a finding ID that no
// longer exists in the findings table (e.g. deleted independently
// after the chain was saved -- Phase 3.31's own adversarial scenario
// 11, "malformed/stale finding references") is still read back
// successfully: Chains().Relations/Candidates never join against the
// findings table, so a stale reference cannot break the read path
// itself -- only a CONSUMER (e.g. the CLI's "chains show", which
// looks up each participating finding separately) needs to handle a
// missing finding gracefully, proven separately in
// tests/e2e/e2e_chains_cli_test.go.
func TestChains_StaleFindingReference_ReadsBackWithoutError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	// Deliberately never create findings "does-not-exist-1"/"-2" --
	// the relation/candidate reference them anyway.
	result := chains.Result{
		Relations: []chains.FindingRelation{
			{ID: "rel1", Type: chains.RelationSameEndpoint, FindingAID: "does-not-exist-1", FindingBID: "does-not-exist-2", ScanJobID: "scan1"},
		},
		Candidates: []chains.ChainCandidate{
			{ID: "cand1", ScanJobID: "scan1", FindingIDs: []string{"does-not-exist-1", "does-not-exist-2"}, RelationIDs: []string{"rel1"}, Status: chains.ChainPotential},
		},
	}
	if err := s.Chains().SaveResult(ctx, "scan1", result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	relations, err := s.Chains().Relations(ctx, "scan1")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(relations) != 1 {
		t.Errorf("expected the stale-referencing relation to still be readable, got %d", len(relations))
	}
	candidates, err := s.Chains().Candidates(ctx, "scan1")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Errorf("expected the stale-referencing candidate to still be readable, got %d", len(candidates))
	}
}

func TestChains_DeterministicReadOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.ScanJobs().Create(ctx, models.ScanJob{ID: "scan1", Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	result := chains.Result{Relations: []chains.FindingRelation{
		{ID: "rel-c", Type: chains.RelationSameEndpoint, FindingAID: "f1", FindingBID: "f2", ScanJobID: "scan1"},
		{ID: "rel-a", Type: chains.RelationSameParameter, FindingAID: "f3", FindingBID: "f4", ScanJobID: "scan1"},
		{ID: "rel-b", Type: chains.RelationSameResource, FindingAID: "f5", FindingBID: "f6", ScanJobID: "scan1"},
	}}
	if err := s.Chains().SaveResult(ctx, "scan1", result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	for i := 0; i < 5; i++ {
		relations, err := s.Chains().Relations(ctx, "scan1")
		if err != nil {
			t.Fatalf("Relations (read %d): %v", i, err)
		}
		if len(relations) != 3 || relations[0].ID != "rel-a" || relations[1].ID != "rel-b" || relations[2].ID != "rel-c" {
			t.Fatalf("read %d: expected deterministic ascending-ID order [rel-a rel-b rel-c], got: %v", i, []string{relations[0].ID, relations[1].ID, relations[2].ID})
		}
	}
}
