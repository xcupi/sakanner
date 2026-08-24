package correlation

import (
	"testing"
)

// Deterministic ordering tests (task section 22).

func TestOrdering_SortedByHostPortPathTypeParameter(t *testing.T) {
	e := NewEngine()
	b := xssFinding("scan-1", "")
	b.Host = "beta.test"
	a := sqliFinding("scan-1", "")
	a.Host = "alpha.test"
	e.Ingest(b, a)

	got := e.Findings()
	if len(got) != 2 {
		t.Fatalf("Findings() = %d, want 2", len(got))
	}
	if got[0].Asset.Host != "alpha.test" || got[1].Asset.Host != "beta.test" {
		t.Errorf("order = [%s, %s], want alpha.test before beta.test", got[0].Asset.Host, got[1].Asset.Host)
	}
}

func TestOrdering_DeterministicRegardlessOfIngestOrder(t *testing.T) {
	e1 := NewEngine()
	e1.Ingest(xssFinding("scan-1", ""), sqliFinding("scan-1", ""), ssrfFinding("scan-1", "tok"))
	got1 := e1.Findings()

	e2 := NewEngine()
	e2.Ingest(ssrfFinding("scan-1", "tok"), xssFinding("scan-1", ""), sqliFinding("scan-1", ""))
	got2 := e2.Findings()

	if len(got1) != len(got2) {
		t.Fatalf("len mismatch: %d vs %d", len(got1), len(got2))
	}
	for i := range got1 {
		if got1[i].FindingID != got2[i].FindingID {
			t.Errorf("index %d: FindingID %q vs %q -- output order must not depend on ingest order", i, got1[i].FindingID, got2[i].FindingID)
		}
	}
}

func TestOrdering_StableAcrossRepeatedCalls(t *testing.T) {
	e := NewEngine()
	e.Ingest(xssFinding("scan-1", ""), sqliFinding("scan-1", ""), ssrfFinding("scan-1", "tok"), idorFinding("scan-1", "r"))

	first := e.Findings()
	second := e.Findings()
	if len(first) != len(second) {
		t.Fatalf("len mismatch across repeated calls")
	}
	for i := range first {
		if first[i].FindingID != second[i].FindingID {
			t.Errorf("index %d: order differs across repeated Findings() calls", i)
		}
	}
}
