package evidence

import (
	"sync"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/internal/risk"
	"sakanner/pkg/models"
)

// Concurrency tests (task section 41) -- run under `go test -race`.
// BuildEvidence/BuildPackage hold no package-level mutable state (every
// function is a pure computation over its arguments plus a fresh
// time.Now() per call), so concurrent use needs no locking to be safe
// -- verified here, not just assumed.

func TestConcurrency_RepeatedBuildEvidenceStaysDeterministic(t *testing.T) {
	cf := fixtureIDOR()
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items := BuildEvidence(cf, DefaultLimits())
			var ids string
			for _, it := range items {
				ids += it.EvidenceID + "|"
			}
			mu.Lock()
			seen[ids] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 1 {
		t.Errorf("observed %d distinct evidence-ID sequences across 100 concurrent BuildEvidence() calls, want exactly 1", len(seen))
	}
}

func TestConcurrency_ConcurrentBuildEvidenceOfDistinctFindings(t *testing.T) {
	fixtures := allSixFixtures()
	var wg sync.WaitGroup
	errs := make(chan string, len(fixtures)*10)
	for i := 0; i < 10; i++ {
		for name, cf := range fixtures {
			name, cf := name, cf
			wg.Add(1)
			go func() {
				defer wg.Done()
				items := BuildEvidence(cf, DefaultLimits())
				if len(items) == 0 {
					errs <- name + ": no evidence produced"
					return
				}
				for _, it := range items {
					if it.FindingID != cf.FindingID {
						errs <- name + ": evidence item carries wrong FindingID (cross-goroutine contamination)"
					}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestConcurrency_ConcurrentBuildPackage(t *testing.T) {
	cf := fixtureSSRF()
	assessment := risk.Assess(cf, nil)

	var wg sync.WaitGroup
	results := make(chan FindingPackage, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- BuildPackage(cf, assessment, DefaultLimits())
		}()
	}
	wg.Wait()
	close(results)

	var first FindingPackage
	first.Summary = ""
	firstSet := false
	for pkg := range results {
		if !firstSet {
			first = pkg
			firstSet = true
			continue
		}
		if pkg.Summary != first.Summary || pkg.WhyVulnerable != first.WhyVulnerable {
			t.Error("concurrent BuildPackage() calls produced different Summary/WhyVulnerable text")
		}
		if len(pkg.Evidence) != len(first.Evidence) {
			t.Fatal("concurrent BuildPackage() calls produced different evidence counts")
		}
		for i := range pkg.Evidence {
			if pkg.Evidence[i].EvidenceID != first.Evidence[i].EvidenceID {
				t.Errorf("index %d: evidence ID differs across concurrent BuildPackage() calls", i)
			}
		}
	}
}

func TestConcurrency_MixedBuildEvidenceAndBuildPackage(t *testing.T) {
	fixtures := allSixFixtures()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		for _, cf := range fixtures {
			cf := cf
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = BuildEvidence(cf, DefaultLimits())
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				a := risk.Assess(cf, nil)
				_ = BuildPackage(cf, a, DefaultLimits())
			}()
		}
	}
	wg.Wait()
}

func TestConcurrency_ConcurrentBuildEvidenceOfIndependentSyntheticFindings(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan string, 50)
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw := rawRequestResponseEvidence{
				Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
				ResponseFragment: "ok", Parameter: "q", Payload: "1",
			}
			cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)
			cf.FindingID = "finding-" + string(rune('a'+i%26))
			items := BuildEvidence(cf, DefaultLimits())
			if len(items) == 0 {
				errs <- "no evidence produced"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestConcurrency_ScopeIsolation_NoCrossFindingLeakage(t *testing.T) {
	// Each goroutine builds evidence for a finding carrying its own
	// unique secret; if any package-level mutable state existed
	// (map, buffer, etc.), -race would flag it and/or a secret from
	// one goroutine could leak into another's output.
	var wg sync.WaitGroup
	errs := make(chan string, correlationConcurrencyN)
	for i := 0; i < correlationConcurrencyN; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret := "unique-secret-" + string(rune('A'+i%26))
			raw := rawRequestResponseEvidence{
				Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
				Headers:          map[string]string{"Authorization": "Bearer " + secret},
				ResponseFragment: "ok", Parameter: "q", Payload: "1",
			}
			cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)
			items := BuildEvidence(cf, DefaultLimits())
			for _, it := range items {
				if it.Request.Headers["Authorization"] == "Bearer "+secret {
					errs <- "secret leaked unredacted"
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

const correlationConcurrencyN = 40

func TestConcurrency_NoSharedStateAcrossCorrelationFindingSlice(t *testing.T) {
	findings := []correlation.CanonicalFinding{fixtureXSS(), fixtureSQLi(), fixtureIDOR()}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		for _, cf := range findings {
			cf := cf
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = BuildEvidence(cf, DefaultLimits())
			}()
		}
	}
	wg.Wait()
}
