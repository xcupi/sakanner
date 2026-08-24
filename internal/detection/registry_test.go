package detection

import (
	"context"
	"testing"

	"sakanner/pkg/models"
)

// stubDetector is the smallest possible Detector implementation, used
// only to test Registry in isolation -- detectiontest.Mock (a separate
// package, deliberately test-support-only) is used for the fuller
// lifecycle tests in engine_test.go.
type stubDetector struct{ id string }

func (s stubDetector) Metadata() Metadata   { return Metadata{ID: s.id, Name: s.id} }
func (s stubDetector) Eligible(Target) bool { return true }
func (s stubDetector) Detect(context.Context, Target, *Executor) (Result, error) {
	return Result{Outcome: OutcomeNoFinding}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubDetector{id: "xss-reflected"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d, ok := r.Get("xss-reflected")
	if !ok {
		t.Fatal("Get: not found after Register")
	}
	if d.Metadata().ID != "xss-reflected" {
		t.Errorf("Metadata().ID = %q, want xss-reflected", d.Metadata().ID)
	}
}

func TestRegistry_GetUnknownIDNotFound(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Get("does-not-exist"); ok {
		t.Error("Get: found a detector that was never registered")
	}
}

func TestRegistry_DuplicateIDRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubDetector{id: "sqli"}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(stubDetector{id: "sqli"}); err == nil {
		t.Error("second Register with the same ID: want error, got nil")
	}
	// The original registration must survive a rejected duplicate attempt.
	if _, ok := r.Get("sqli"); !ok {
		t.Error("original registration was lost after a rejected duplicate Register")
	}
}

func TestRegistry_EmptyIDRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubDetector{id: ""}); err == nil {
		t.Error("Register with empty ID: want error, got nil")
	}
}

func TestRegistry_NilDetectorRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("Register(nil): want error, got nil")
	}
}

func TestRegistry_SetEnabledDisablesWithoutRemoving(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(stubDetector{id: "ssrf"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !r.Enabled("ssrf") {
		t.Fatal("a freshly registered detector should default to enabled")
	}
	if err := r.SetEnabled("ssrf", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if r.Enabled("ssrf") {
		t.Error("Enabled: still true after SetEnabled(false)")
	}
	if _, ok := r.Get("ssrf"); !ok {
		t.Error("Get: detector was removed by SetEnabled(false), should only be disabled")
	}
	if err := r.SetEnabled("ssrf", true); err != nil {
		t.Fatalf("re-enabling: %v", err)
	}
	if !r.Enabled("ssrf") {
		t.Error("Enabled: still false after SetEnabled(true)")
	}
}

func TestRegistry_SetEnabledUnknownIDErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.SetEnabled("never-registered", false); err == nil {
		t.Error("SetEnabled on an unregistered ID: want error, got nil")
	}
}

func TestRegistry_ListReflectsEnabledState(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a"})
	_ = r.Register(stubDetector{id: "b"})
	_ = r.SetEnabled("b", false)

	entries := r.List()
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
	byID := map[string]Entry{}
	for _, e := range entries {
		byID[e.Metadata.ID] = e
	}
	if !byID["a"].Enabled {
		t.Error("a should be enabled")
	}
	if byID["b"].Enabled {
		t.Error("b should be disabled")
	}
}

func TestRegistry_EmptyRegistryListsNothing(t *testing.T) {
	r := NewRegistry()
	if entries := r.List(); len(entries) != 0 {
		t.Errorf("List on an empty registry = %+v, want empty (no fake detectors)", entries)
	}
}

func TestRegistry_EnabledDetectorsExcludesDisabled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "keep"})
	_ = r.Register(stubDetector{id: "drop"})
	_ = r.SetEnabled("drop", false)

	got := r.enabledDetectors()
	if len(got) != 1 || got[0].Metadata().ID != "keep" {
		t.Errorf("enabledDetectors() = %+v, want only \"keep\"", got)
	}
}

// sanity: Metadata carries DefaultSeverity correctly through the
// registry round trip (guards against a copy/interface-boxing bug
// silently dropping fields).
func TestRegistry_MetadataRoundTrips(t *testing.T) {
	r := NewRegistry()
	d := stubDetectorWithSeverity{id: "info-leak", severity: models.SeverityMedium}
	if err := r.Register(d); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, _ := r.Get("info-leak")
	if got.Metadata().DefaultSeverity != models.SeverityMedium {
		t.Errorf("DefaultSeverity = %q, want medium", got.Metadata().DefaultSeverity)
	}
}

type stubDetectorWithSeverity struct {
	id       string
	severity models.Severity
}

func (s stubDetectorWithSeverity) Metadata() Metadata {
	return Metadata{ID: s.id, DefaultSeverity: s.severity}
}
func (s stubDetectorWithSeverity) Eligible(Target) bool { return true }
func (s stubDetectorWithSeverity) Detect(context.Context, Target, *Executor) (Result, error) {
	return Result{Outcome: OutcomeNoFinding}, nil
}
