package evidence

import (
	"strconv"
	"testing"
	"time"

	"sakanner/internal/correlation"
	"sakanner/internal/risk"
	"sakanner/pkg/models"
)

// Performance tests (task section 40): evidence building, sanitization,
// hashing, and package assembly must scale linearly (or near it) with
// the number of findings, never O(n^2) or worse.

func findingSetForPerf(n int) []correlation.CanonicalFinding {
	out := make([]correlation.CanonicalFinding, n)
	for i := 0; i < n; i++ {
		idx := strconv.Itoa(i)
		raw := rawRequestResponseEvidence{
			Request:  "GET http://host-" + strconv.Itoa(i%20) + ".test/search?q=probe" + idx,
			Response: "HTTP 200", StatusCode: 200,
			Headers:          map[string]string{"Content-Type": "text/html", "Authorization": "Bearer secret-" + idx},
			ResponseFragment: "<div>results for probe" + idx + "</div>",
			Parameter:        "q", Payload: "probe" + idx,
			Observation: "context=html reflected=true note=" + idx,
			Reason:      "the payload was reflected unescaped in an HTML text context",
		}
		out[i] = findingWith("reflected_xss", "host-"+strconv.Itoa(i%20)+".test", "/search", "q", models.SeverityHigh, 0.9, raw)
		out[i].FindingID = "finding-" + idx
	}
	return out
}

func benchmarkBuildEvidence(t *testing.T, n int) time.Duration {
	t.Helper()
	findings := findingSetForPerf(n)
	limits := DefaultLimits()
	start := time.Now()
	total := 0
	for _, cf := range findings {
		items := BuildEvidence(cf, limits)
		total += len(items)
	}
	elapsed := time.Since(start)
	if total == 0 {
		t.Fatal("no evidence produced across the whole set")
	}
	return elapsed
}

func benchmarkBuildPackage(t *testing.T, n int) time.Duration {
	t.Helper()
	findings := findingSetForPerf(n)
	limits := DefaultLimits()
	start := time.Now()
	for _, cf := range findings {
		assessment := risk.Assess(cf, nil)
		pkg := BuildPackage(cf, assessment, limits)
		if pkg.Summary == "" {
			t.Fatal("empty Summary")
		}
	}
	return time.Since(start)
}

func TestPerformance_BuildEvidence_10Findings(t *testing.T) {
	elapsed := benchmarkBuildEvidence(t, 10)
	t.Logf("10 findings: %s", elapsed)
}

func TestPerformance_BuildEvidence_100Findings(t *testing.T) {
	elapsed := benchmarkBuildEvidence(t, 100)
	t.Logf("100 findings: %s", elapsed)
}

// Thresholds below are deliberately generous (not tight benchmarks):
// this package does real regex-based redaction, JSON marshal/unmarshal,
// and SHA-256 hashing per evidence item -- heavier than a pure
// arithmetic computation -- and the project's standard regression run
// is `go test -race ./...`, where the race detector's per-memory-access
// instrumentation routinely costs 5-10x. The thresholds are sized to
// hold comfortably under -race while still catching real O(n^2)
// regressions (which would blow well past any of them, race or not).

func TestPerformance_BuildEvidence_1000Findings(t *testing.T) {
	elapsed := benchmarkBuildEvidence(t, 1000)
	t.Logf("1000 findings: %s", elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("1000 findings took %s, want well under 5s", elapsed)
	}
}

func TestPerformance_BuildEvidence_10000Findings(t *testing.T) {
	elapsed := benchmarkBuildEvidence(t, 10000)
	t.Logf("10000 findings: %s", elapsed)
	if elapsed > 20*time.Second {
		t.Errorf("10000 findings took %s, want well under 20s (possible O(n^2) behavior)", elapsed)
	}
}

func TestPerformance_BuildEvidence_ScalesSubQuadratically(t *testing.T) {
	small := benchmarkBuildEvidence(t, 500)
	large := benchmarkBuildEvidence(t, 5000)
	t.Logf("500 findings: %s, 5000 findings: %s", small, large)
	if small > 0 && large > small*50 {
		t.Errorf("scaling looks worse than expected: 500=%s 5000=%s (ratio %.1fx for a 10x input increase)", small, large, float64(large)/float64(small))
	}
}

func TestPerformance_BuildPackage_1000Findings(t *testing.T) {
	elapsed := benchmarkBuildPackage(t, 1000)
	t.Logf("1000 findings (full package): %s", elapsed)
	if elapsed > 6*time.Second {
		t.Errorf("1000 findings (BuildPackage) took %s, want well under 6s", elapsed)
	}
}
