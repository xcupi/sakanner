package correlation

import (
	"fmt"
	"sync"
	"testing"

	"sakanner/pkg/models"
)

// Concurrency tests (task section 32) -- run under `go test -race`.

func TestConcurrency_ConcurrentInsertNoDataRace(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := sqliFinding("scan-1", "")
			f.AffectedEndpoint = fmt.Sprintf("/endpoint-%d", i)
			e.Ingest(f)
		}()
	}
	wg.Wait()

	got := e.Findings()
	if len(got) != 50 {
		t.Fatalf("Findings() = %d, want 50 (one per distinct endpoint, no lost or duplicated inserts)", len(got))
	}
}

func TestConcurrency_ConcurrentDeduplicationNoDuplicateCanonicalRecords(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Ingest(sqliFinding("scan-1", "")) // identical identity every time
		}()
	}
	wg.Wait()

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1 (200 concurrent submissions of the identical finding must still collapse to one canonical record)", len(got))
	}
}

func TestConcurrency_ConcurrentEvidenceMergeNoDataRace(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := sqliFinding("scan-1", "") // identical identity
			f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, fmt.Sprintf("evidence-%d", i%10))}
			e.Ingest(f)
		}()
	}
	wg.Wait()

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
	if len(got[0].Evidence) != 10 {
		t.Errorf("Evidence count = %d, want 10 distinct items (evidence-0..evidence-9)", len(got[0].Evidence))
	}
}

func TestConcurrency_ConcurrentScanCompletionNoCrossScanLeak(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	const scans = 20
	for s := 0; s < scans; s++ {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Ingest(sqliFinding(fmt.Sprintf("scan-%d", s), ""))
		}()
	}
	wg.Wait()

	got := e.Findings()
	if len(got) != scans {
		t.Fatalf("Findings() = %d, want %d (one per independent scan, no cross-scan merging)", len(got), scans)
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.ScanID] {
			t.Errorf("ScanID %q appeared more than once", f.ScanID)
		}
		seen[f.ScanID] = true
	}
}

func TestConcurrency_MixedConcurrentReadAndWrite(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := sqliFinding("scan-1", "")
			f.AffectedEndpoint = fmt.Sprintf("/e%d", i%20)
			e.Ingest(f)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.Findings() // concurrent reads while writes are in flight
		}()
	}
	wg.Wait()

	got := e.Findings()
	if len(got) != 20 {
		t.Fatalf("Findings() = %d, want 20", len(got))
	}
}
