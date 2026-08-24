package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// TestWithTx_PartialWriteRollsBackOnConstraintViolation proves a
// transaction that writes several rows successfully and then hits a
// genuine DB-level constraint violation (a duplicate primary key, not a
// Go-level early return) rolls back ALL of it -- no partial data
// survives a failed transaction, even when the failure comes from SQLite
// itself rather than application logic.
func TestWithTx_PartialWriteRollsBackOnConstraintViolation(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	// Pre-existing row that a later insert inside the transaction will
	// collide with.
	if err := s.Targets().Create(ctx, models.Target{ID: "collide", Value: "existing.com", Type: models.TargetTypeDomain, CreatedAt: now}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = s.WithTx(ctx, func(tx storage.Store) error {
		// This one succeeds...
		if err := tx.Targets().Create(ctx, models.Target{ID: "t1", Value: "one.com", Type: models.TargetTypeDomain, CreatedAt: now}); err != nil {
			return err
		}
		if err := tx.Targets().Create(ctx, models.Target{ID: "t2", Value: "two.com", Type: models.TargetTypeDomain, CreatedAt: now}); err != nil {
			return err
		}
		// ...this one hits a genuine primary-key collision at the SQLite
		// level and must abort the whole transaction.
		return tx.Targets().Create(ctx, models.Target{ID: "collide", Value: "attacker-controlled.com", Type: models.TargetTypeDomain, CreatedAt: now})
	})
	if err == nil {
		t.Fatal("expected WithTx to return an error for the primary-key collision")
	}

	// Neither t1 nor t2 -- successfully written earlier in the SAME
	// transaction -- may have survived the rollback.
	if _, err := s.Targets().Get(ctx, "t1"); err != storage.ErrNotFound {
		t.Errorf("t1: err = %v, want ErrNotFound (partial write from a rolled-back transaction must not persist)", err)
	}
	if _, err := s.Targets().Get(ctx, "t2"); err != storage.ErrNotFound {
		t.Errorf("t2: err = %v, want ErrNotFound (partial write from a rolled-back transaction must not persist)", err)
	}

	// The original row must be untouched, not overwritten by the
	// colliding insert attempt.
	original, err := s.Targets().Get(ctx, "collide")
	if err != nil {
		t.Fatalf("Get collide: %v", err)
	}
	if original.Value != "existing.com" {
		t.Errorf("collide.Value = %q, want %q (original row must survive untouched)", original.Value, "existing.com")
	}

	// The store must remain fully usable afterward.
	if err := s.Ping(ctx); err != nil {
		t.Errorf("store unusable after rolled-back transaction: %v", err)
	}
}
