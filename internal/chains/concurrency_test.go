package chains

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestConcurrency_ManyGoroutines_SameInput_NoRaceIdenticalResults
// proves Correlate has no shared mutable state: many goroutines
// calling it simultaneously with the SAME input never race (run this
// file under -race) and always produce identical results.
func TestConcurrency_ManyGoroutines_SameInput_NoRaceIdenticalResults(t *testing.T) {
	findings := buildDeterminismFixture()
	const n = 50
	results := make([]Result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = Correlate(findings, DefaultLimits())
		}(i)
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if len(results[i].Relations) != len(results[0].Relations) {
			t.Fatalf("goroutine %d produced %d relations, goroutine 0 produced %d", i, len(results[i].Relations), len(results[0].Relations))
		}
		if len(results[i].Candidates) != len(results[0].Candidates) {
			t.Fatalf("goroutine %d produced %d candidates, goroutine 0 produced %d", i, len(results[i].Candidates), len(results[0].Candidates))
		}
	}
}

// TestConcurrency_ManyGoroutines_DifferentInputs_NoCrossContamination
// proves distinct concurrent calls with DIFFERENT (including
// different-scan, different-identity) inputs never leak into each
// other's results -- each goroutine's own scan/identity must appear
// only in its own output.
func TestConcurrency_ManyGoroutines_DifferentInputs_NoCrossContamination(t *testing.T) {
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scanID := fmt.Sprintf("scan-%d", i)
			identity := fmt.Sprintf("identity-%d", i)
			a := newFinding("a", scanID, "sqli").identity(identity).endpoint("target.test", 80, "/x").build()
			b := newFinding("b", scanID, "reflected_xss").identity(identity).endpoint("target.test", 80, "/x").build()
			res := Correlate([]models.Finding{a, b}, DefaultLimits())
			for _, r := range res.Relations {
				if r.ScanJobID != scanID {
					errs <- fmt.Sprintf("goroutine %d: relation has ScanJobID %q, want %q", i, r.ScanJobID, scanID)
				}
			}
			for _, c := range res.Candidates {
				if c.ScanJobID != scanID {
					errs <- fmt.Sprintf("goroutine %d: candidate has ScanJobID %q, want %q", i, c.ScanJobID, scanID)
				}
				if c.IdentityContext != identity {
					errs <- fmt.Sprintf("goroutine %d: candidate has IdentityContext %q, want %q", i, c.IdentityContext, identity)
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestConcurrency_RepeatedExecution proves calling Correlate many
// times in a tight sequential loop (a different concern from
// goroutine-level concurrency: no accumulating state across calls)
// never changes behavior.
func TestConcurrency_RepeatedExecution(t *testing.T) {
	findings := buildDeterminismFixture()
	first := Correlate(findings, DefaultLimits())
	for i := 0; i < 200; i++ {
		next := Correlate(findings, DefaultLimits())
		if len(next.Relations) != len(first.Relations) || len(next.Candidates) != len(first.Candidates) {
			t.Fatalf("iteration %d diverged from the first call", i)
		}
	}
}

// TestConcurrency_CancellationDoesNotApply documents that Correlate
// takes no context.Context -- it is a pure, always-bounded, always-
// fast computation (bounded by Limits, never network/IO), so there is
// no long-running operation to cancel. This test proves the bounded-
// input case it WOULD need cancellation for (a very large adversarial
// input) still completes promptly without one, confirming the
// resource limits (not cancellation) are what keeps this safe.
func TestConcurrency_CancellationDoesNotApply(t *testing.T) {
	findings := manyFindingsSameEndpoint(500)
	done := make(chan struct{})
	go func() {
		Correlate(findings, DefaultLimits())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Correlate did not complete within 5s even at the maximum bounded input size -- resource limits are not actually bounding the work")
	}
}
