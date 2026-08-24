package correlation

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// Resource exhaustion tests (task section 31).

func TestPerformance_ThousandsOfDistinctFindings(t *testing.T) {
	e := NewEngine()
	start := time.Now()
	for i := 0; i < 5000; i++ {
		f := sqliFinding("scan-1", "")
		f.AffectedEndpoint = fmt.Sprintf("/endpoint-%d", i)
		e.Ingest(f)
	}
	elapsed := time.Since(start)
	t.Logf("5000 distinct findings ingested in %s", elapsed)

	got := e.Findings()
	if len(got) != 5000 {
		t.Fatalf("Findings() = %d, want 5000", len(got))
	}
	if elapsed > 5*time.Second {
		t.Errorf("ingest took %s, want well under 5s for 5000 findings (possible quadratic behavior)", elapsed)
	}
}

func TestPerformance_ThousandsOfDuplicateFindings(t *testing.T) {
	e := NewEngine()
	start := time.Now()
	for i := 0; i < 10000; i++ {
		e.Ingest(sqliFinding("scan-1", ""))
	}
	elapsed := time.Since(start)
	t.Logf("10000 duplicate findings ingested in %s", elapsed)

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1 (all duplicates of the same identity)", len(got))
	}
	if len(got[0].Evidence) > maxEvidenceItemsPerFinding {
		t.Errorf("Evidence count = %d, want <= %d (bounded regardless of duplicate volume)", len(got[0].Evidence), maxEvidenceItemsPerFinding)
	}
	if elapsed > 5*time.Second {
		t.Errorf("ingest took %s, want well under 5s for 10000 duplicates (possible quadratic behavior)", elapsed)
	}
}

func TestPerformance_VeryLargeEvidenceSets(t *testing.T) {
	e := NewEngine()
	start := time.Now()
	for i := 0; i < 2000; i++ {
		f := sqliFinding("scan-1", "")
		f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, fmt.Sprintf("distinct-%d", i))}
		e.Ingest(f)
	}
	elapsed := time.Since(start)
	t.Logf("2000 distinct-evidence submissions to ONE identity ingested in %s", elapsed)

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
	if len(got[0].Evidence) > maxEvidenceItemsPerFinding {
		t.Errorf("Evidence count = %d, want <= %d", len(got[0].Evidence), maxEvidenceItemsPerFinding)
	}
}

func TestPerformance_NoUnboundedMemoryGrowthFromDuplicates(t *testing.T) {
	// Bucket count must stay at 1 (bounded groups map) no matter how
	// many times the SAME identity+evidence is resubmitted -- this is
	// what actually protects memory, independent of timing.
	e := NewEngine()
	for i := 0; i < 20000; i++ {
		e.Ingest(sqliFinding("scan-1", ""))
	}
	if e.Len() != 1 {
		t.Errorf("Engine.Len() = %d, want 1", e.Len())
	}
}

func TestPerformance_RepeatedDuplicateSubmissionsStayBounded(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	e := NewEngine()
	for i := 0; i < 50000; i++ {
		e.Ingest(sqliFinding("scan-1", ""))
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)
	grew := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	t.Logf("heap grew by %d bytes after 50000 duplicate submissions", grew)
	// A generous ceiling -- this is a smoke test against genuinely
	// unbounded growth (e.g. an accidental O(n) evidence slice), not a
	// tight budget.
	if grew > 50*1024*1024 {
		t.Errorf("heap grew by %d bytes, want well under 50MB for 50000 duplicate submissions to one identity", grew)
	}
}
