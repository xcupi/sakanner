package sstiactive

import "testing"

func TestContainsIsolatedNumber_ExactStandaloneMatch_True(t *testing.T) {
	if !containsIsolatedNumber([]byte("Hello, 3589!"), "3589") {
		t.Error("expected a standalone numeric token to match")
	}
}

func TestContainsIsolatedNumber_AtStringBoundaries_True(t *testing.T) {
	if !containsIsolatedNumber([]byte("3589"), "3589") {
		t.Error("expected an exact whole-body match to match")
	}
}

func TestContainsIsolatedNumber_PartOfLargerNumber_False(t *testing.T) {
	for _, body := range []string{"13589", "35890", "135890", "x35890x"} {
		if containsIsolatedNumber([]byte(body), "3589") {
			t.Errorf("SECURITY: %q incorrectly matched as containing standalone %q -- it only contains it as a substring of a larger number", body, "3589")
		}
	}
}

func TestContainsIsolatedNumber_NotPresent_False(t *testing.T) {
	if containsIsolatedNumber([]byte("Hello, world!"), "3589") {
		t.Error("expected no match when the number is entirely absent")
	}
}

func TestContainsIsolatedNumber_MultipleOccurrences_OneIsolated_True(t *testing.T) {
	// "13589" (embedded, must not count) then " 3589" (standalone, must count).
	if !containsIsolatedNumber([]byte("id=13589 result=3589"), "3589") {
		t.Error("expected the standalone occurrence to be found even though an embedded one precedes it")
	}
}

func TestContainsIsolatedNumber_EmptyTarget_False(t *testing.T) {
	if containsIsolatedNumber([]byte("anything"), "") {
		t.Error("expected an empty target string to never match")
	}
}

func TestRandomOperands_DistinctAndInPool(t *testing.T) {
	for i := 0; i < 50; i++ {
		a, b := randomOperands()
		if a == b {
			t.Errorf("randomOperands returned equal operands: %d, %d", a, b)
		}
		foundA, foundB := false, false
		for _, p := range operandPrimes {
			if p == a {
				foundA = true
			}
			if p == b {
				foundB = true
			}
		}
		if !foundA || !foundB {
			t.Errorf("randomOperands returned an operand outside the fixed pool: %d, %d", a, b)
		}
	}
}
