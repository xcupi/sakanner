package sqlite

import (
	"context"
	"testing"
)

// TestNew_InvalidPathReturnsErrorNotPanic proves opening a database at
// an unusable path (e.g. a nonexistent directory) fails with a plain
// error, not a panic -- part of Phase 2 acceptance testing's database
// failure-handling checks.
func TestNew_InvalidPathReturnsErrorNotPanic(t *testing.T) {
	_, err := New(context.Background(), "/nonexistent-directory-xyz-sakanner-test/sakanner.db")
	if err == nil {
		t.Fatal("expected an error opening a database at an unusable path, got nil")
	}
}

// TestStore_UseAfterCloseReturnsErrorNotPanic proves every repository
// call against an already-closed Store fails with a plain error, not a
// panic -- relevant since orchestration.Pipeline holds a Store for the
// whole run and any code path that raced with a Close would otherwise
// crash the process instead of failing that one operation.
func TestStore_UseAfterCloseReturnsErrorNotPanic(t *testing.T) {
	store, err := New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := store.Targets().List(context.Background()); err == nil {
		t.Error("Targets().List() after Close() = nil error, want an error")
	}
}
