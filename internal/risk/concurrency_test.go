package risk

import (
	"sync"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Concurrency tests (task section 27) -- run under `go test -race`.
// Score/Assess/Rank hold no package-level mutable state at all (every
// function is a pure computation over its arguments), so concurrent
// use needs no locking to be safe -- verified here, not just assumed.

func TestConcurrency_ConcurrentScoring(t *testing.T) {
	factors := RiskFactors{Severity: models.SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationVerified, Exposure: ExposureInternetFacing}
	var wg sync.WaitGroup
	results := make(chan ScoreBreakdown, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- Score(factors)
		}()
	}
	wg.Wait()
	close(results)

	for b := range results {
		if b.RiskScore != 70 {
			t.Errorf("concurrent Score() = %d, want 70", b.RiskScore)
		}
	}
}

func TestConcurrency_ConcurrentAssessment(t *testing.T) {
	cf, ctx := fixtureCriticalHighInternetFacing()
	// This fixture is correlation.StatusNew with 0.95 confidence, so
	// DeriveFactors derives SUSPICIOUS (not VERIFIED -- that requires
	// StatusConfirmed, see derive.go) -- 90 x 1.00 x 0.85 x 1.00 =
	// 76.5, which rounds to 77.
	const wantScore = 77
	var wg sync.WaitGroup
	results := make(chan Assessment, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- Assess(cf, ctx)
		}()
	}
	wg.Wait()
	close(results)

	for a := range results {
		if a.RiskScore != wantScore {
			t.Errorf("concurrent Assess() RiskScore = %d, want %d", a.RiskScore, wantScore)
		}
	}
}

func TestConcurrency_ConcurrentRanking(t *testing.T) {
	findings := findingSet(50)
	assessments := AssessAll(findings, nil)

	var wg sync.WaitGroup
	results := make(chan []Assessment, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- Rank(assessments)
		}()
	}
	wg.Wait()
	close(results)

	var first []Assessment
	for ranked := range results {
		if first == nil {
			first = ranked
			continue
		}
		if len(ranked) != len(first) {
			t.Fatal("concurrent Rank() calls produced different lengths")
		}
		for i := range ranked {
			if ranked[i].FindingID != first[i].FindingID {
				t.Fatalf("concurrent Rank() calls produced different orders at index %d", i)
			}
		}
	}
}

func TestConcurrency_RepeatedScoringStaysDeterministic(t *testing.T) {
	cf, ctx := fixtureMediumVerifiedInternetFacing()
	var wg sync.WaitGroup
	var mu sync.Mutex
	scores := map[int]bool{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := Assess(cf, ctx)
			mu.Lock()
			scores[a.RiskScore] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(scores) != 1 {
		t.Errorf("observed %d distinct scores across 50 concurrent Assess() calls, want exactly 1", len(scores))
	}
}

func TestConcurrency_MixedAssessAndRank(t *testing.T) {
	findings := findingSet(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assessments := AssessAll(findings, nil)
			_ = Rank(assessments)
		}()
	}
	wg.Wait()
}

func TestConcurrency_ConcurrentAssessAllOfDistinctFindingSets(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan string, 20)
	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings := []correlation.CanonicalFinding{
				canonicalFinding("scan-1", "f-"+string(rune('a'+i)), "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test"),
			}
			got := AssessAll(findings, nil)
			if len(got) != 1 {
				errs <- "unexpected length"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
