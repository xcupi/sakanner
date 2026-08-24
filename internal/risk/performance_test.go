package risk

import (
	"strconv"
	"testing"
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Performance tests (task section 26).

func findingSet(n int) []correlation.CanonicalFinding {
	out := make([]correlation.CanonicalFinding, n)
	for i := 0; i < n; i++ {
		out[i] = canonicalFinding("scan-1", "f-"+strconv.Itoa(i), "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "host-"+strconv.Itoa(i%20)+".test")
	}
	return out
}

func benchmarkAssessAndRank(t *testing.T, n int) time.Duration {
	t.Helper()
	findings := findingSet(n)
	start := time.Now()
	assessments := AssessAll(findings, nil)
	ranked := Rank(assessments)
	elapsed := time.Since(start)
	if len(ranked) != n {
		t.Fatalf("len(ranked) = %d, want %d", len(ranked), n)
	}
	return elapsed
}

func TestPerformance_10Findings(t *testing.T) {
	elapsed := benchmarkAssessAndRank(t, 10)
	t.Logf("10 findings: %s", elapsed)
}

func TestPerformance_100Findings(t *testing.T) {
	elapsed := benchmarkAssessAndRank(t, 100)
	t.Logf("100 findings: %s", elapsed)
}

func TestPerformance_1000Findings(t *testing.T) {
	elapsed := benchmarkAssessAndRank(t, 1000)
	t.Logf("1000 findings: %s", elapsed)
	if elapsed > 2*time.Second {
		t.Errorf("1000 findings took %s, want well under 2s", elapsed)
	}
}

func TestPerformance_10000Findings(t *testing.T) {
	elapsed := benchmarkAssessAndRank(t, 10000)
	t.Logf("10000 findings: %s", elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("10000 findings took %s, want well under 5s (possible O(n^2) behavior)", elapsed)
	}
}

func TestPerformance_ScalesSubQuadratically(t *testing.T) {
	// A rough smoke test against O(n^2): 10x the input should not take
	// more than roughly 20x the time (a true O(n^2) algorithm would
	// take ~100x).
	small := benchmarkAssessAndRank(t, 500)
	large := benchmarkAssessAndRank(t, 5000)
	t.Logf("500 findings: %s, 5000 findings: %s", small, large)
	if small > 0 && large > small*30 {
		t.Errorf("scaling looks worse than expected: 500=%s 5000=%s (ratio %.1fx for a 10x input increase)", small, large, float64(large)/float64(small))
	}
}
