package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

func TestScopeRuleCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	rule := models.ScopeRule{ID: "r1", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, Note: "test", CreatedAt: now}
	if err := s.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.ScopeRules().Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Value != "example.com" || got.Type != models.ScopeRuleDomainSuffix || got.Action != models.ScopeActionAllow || got.Note != "test" {
		t.Errorf("Get = %+v, want the created rule", got)
	}

	list, err := s.ScopeRules().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d rules, want 1", len(list))
	}

	if err := s.ScopeRules().Delete(ctx, "r1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.ScopeRules().Get(ctx, "r1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

// TestScopeRuleDelete_NonexistentID_ReturnsErrNotFound is the direct
// regression test for the Phase 3.11.1 bug: DELETE FROM ... WHERE id =
// ? matching zero rows previously returned a nil error (SQLite itself
// never errors on a no-op DELETE), so the CLI printed "removed scope
// rule <id>" for ANY input, existent or not, with no mutation actually
// occurring. scopeRuleRepo.Delete must check RowsAffected and return
// storage.ErrNotFound when nothing matched, exactly like
// scanJobRepo.Delete already does.
func TestScopeRuleDelete_NonexistentID_ReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, id := range []string{
		"?", "missing-id", "00000000-0000-0000-0000-000000000000",
		"", "not-a-uuid-at-all", "1fe4cb6e-1364-48f9-ae1f-9fe3788e4551",
	} {
		if err := s.ScopeRules().Delete(ctx, id); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("Delete(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestScopeRuleDelete_OnlyAffectsExactMatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	a := models.ScopeRule{ID: "a", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: now}
	b := models.ScopeRule{ID: "b", Value: "api.example.com", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: now}
	if err := s.ScopeRules().Create(ctx, a); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := s.ScopeRules().Create(ctx, b); err != nil {
		t.Fatalf("create b: %v", err)
	}

	if err := s.ScopeRules().Delete(ctx, "a"); err != nil {
		t.Fatalf("delete a: %v", err)
	}
	if _, err := s.ScopeRules().Get(ctx, "a"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("a should be gone: err = %v", err)
	}
	if _, err := s.ScopeRules().Get(ctx, "b"); err != nil {
		t.Errorf("b must survive removing a: %v", err)
	}
}

func TestScopeRuleDelete_AllowAndDenyOnSameValue_RemovingOneLeavesOther(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	allow := models.ScopeRule{ID: "allow-1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: now}
	deny := models.ScopeRule{ID: "deny-1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionDeny, CreatedAt: now}
	if err := s.ScopeRules().Create(ctx, allow); err != nil {
		t.Fatalf("create allow: %v", err)
	}
	if err := s.ScopeRules().Create(ctx, deny); err != nil {
		t.Fatalf("create deny: %v", err)
	}

	if err := s.ScopeRules().Delete(ctx, "allow-1"); err != nil {
		t.Fatalf("delete allow: %v", err)
	}
	if _, err := s.ScopeRules().Get(ctx, "deny-1"); err != nil {
		t.Errorf("deny-1 must survive removing allow-1: %v", err)
	}
}

// TestScopeRuleCreate_DuplicatesAllowed documents and locks in the
// existing, intentional storage-layer behavior: no uniqueness
// constraint exists on (value, type, action) for scope_rules (see
// internal/storage/migrations/0001_init.sql -- only `id` is a PRIMARY
// KEY). Two rules with identical value/type/action, each its own UUID,
// are both stored independently. Phase 3.11.1 does not change this;
// see docs/phase-3-11-1-cli-ux.md "Duplicate rules" for why.
func TestScopeRuleCreate_DuplicatesAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	r1 := models.ScopeRule{ID: "dup-1", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: now}
	r2 := models.ScopeRule{ID: "dup-2", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: now}
	if err := s.ScopeRules().Create(ctx, r1); err != nil {
		t.Fatalf("create r1: %v", err)
	}
	if err := s.ScopeRules().Create(ctx, r2); err != nil {
		t.Fatalf("create r2 (identical value/type/action): %v", err)
	}

	list, err := s.ScopeRules().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List returned %d rules, want 2 (duplicates are allowed)", len(list))
	}
}
