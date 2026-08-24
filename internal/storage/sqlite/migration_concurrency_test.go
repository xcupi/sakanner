package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"sakanner/pkg/models"
)

// TestMigrate_ConcurrentFreshDatabase_NoRace is the direct regression
// test for the Phase 3.11.1 concurrency bug found via real CLI
// testing: several `scanner` processes starting up concurrently
// against the SAME, brand-new (not-yet-migrated) database file each
// independently read "0 migrations applied" via a plain read before
// any of them held a write lock, then all raced to apply migration
// 0001 -- producing "table already exists"/"duplicate column" errors
// for every loser. sqlite.New() (which calls storage.Migrate
// internally) opens its own independent *sql.DB per call, exactly
// mirroring what happens when multiple separate OS processes each
// open the same file -- this test drives that with real goroutines
// each calling New() against the identical path, which is the
// smallest reproduction that doesn't require actually forking
// processes (see tests/e2e's own subprocess-level coverage for that).
func TestMigrate_ConcurrentFreshDatabase_NoRace(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "concurrent.db")
	const n = 15

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := New(context.Background(), dsn)
			if err != nil {
				errs[i] = err
				return
			}
			defer s.Close()
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: New() failed: %v", i, err)
		}
	}
}

// TestMigrate_ConcurrentFreshDatabase_DataSurvives goes one step
// further: each concurrent "process" also performs a real write
// (adding a scope rule) immediately after opening -- confirming not
// just that migration itself doesn't race, but that the database is
// left in a fully usable, non-corrupted state afterward, with every
// concurrent write actually persisted (task section 25: "verify no
// corrupted state").
func TestMigrate_ConcurrentFreshDatabase_DataSurvives(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "concurrent-write.db")
	const n = 10

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			s, err := New(ctx, dsn)
			if err != nil {
				errs[i] = err
				return
			}
			defer s.Close()

			rule := models.ScopeRule{ID: fmt.Sprintf("rule-%d", i), Value: "10.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}
			errs[i] = s.ScopeRules().Create(ctx, rule)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// One final, fresh connection confirms the persisted state is
	// exactly n rules, no more, no less, no corruption.
	final, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("final New(): %v", err)
	}
	defer final.Close()

	rules, err := final.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != n {
		t.Errorf("len(rules) = %d, want %d", len(rules), n)
	}
}
