package chains

import (
	"math/rand"
	"reflect"
	"testing"

	"sakanner/pkg/models"
)

func buildDeterminismFixture() []models.Finding {
	return []models.Finding{
		newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").identity("account-a").build(),
		newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").identity("account-a").build(),
		newFinding("f3", "scan1", "idor").identity("account-a").param("id").
			url("http://target.test/y?id=OBJ-5541").build(),
		newFinding("f4", "scan1", "info_exposure").identity("account-a").
			evidence("leaked_id=OBJ-5541").build(),
		newFinding("f5", "scan1", "ssrf").endpoint("other.test", 80, "/z").
			evidence("callback confirmed: reached internal.scanner.test").build(),
		newFinding("f6", "scan1", "path_traversal").endpoint("internal.scanner.test", 80, "/w").build(),
		newFinding("f7", "scan-other", "sqli").endpoint("target.test", 80, "/x").build(),
		newFinding("f8", "scan1", "cmdinjection").identity("account-b").endpoint("target.test", 80, "/x").build(),
	}
}

func TestDeterminism_RepeatedCalls_IdenticalOutput(t *testing.T) {
	findings := buildDeterminismFixture()
	first := Correlate(findings, DefaultLimits())
	for i := 0; i < 10; i++ {
		next := Correlate(findings, DefaultLimits())
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("run %d produced different output than run 0:\nfirst=%+v\nnext=%+v", i, first, next)
		}
	}
}

func TestDeterminism_ShuffledInputOrder_IdenticalOutput(t *testing.T) {
	base := buildDeterminismFixture()
	first := Correlate(base, DefaultLimits())

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10; i++ {
		shuffled := make([]models.Finding, len(base))
		copy(shuffled, base)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		next := Correlate(shuffled, DefaultLimits())
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("shuffle %d produced different output than the unshuffled input:\nfirst=%+v\nnext=%+v", i, first, next)
		}
	}
}

func TestDeterminism_IdenticalConfidenceValues(t *testing.T) {
	findings := buildDeterminismFixture()
	a := Correlate(findings, DefaultLimits())
	b := Correlate(findings, DefaultLimits())
	if len(a.Relations) != len(b.Relations) {
		t.Fatalf("relation count differs: %d vs %d", len(a.Relations), len(b.Relations))
	}
	for i := range a.Relations {
		if a.Relations[i].Confidence != b.Relations[i].Confidence {
			t.Errorf("relation %d confidence differs: %v vs %v", i, a.Relations[i].Confidence, b.Relations[i].Confidence)
		}
	}
	for i := range a.Candidates {
		if a.Candidates[i].Confidence != b.Candidates[i].Confidence {
			t.Errorf("candidate %d confidence differs: %v vs %v", i, a.Candidates[i].Confidence, b.Candidates[i].Confidence)
		}
	}
}
