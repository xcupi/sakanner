package evidence

import (
	"testing"
	"time"
)

func sampleHashInput() canonicalHashInput {
	return canonicalHashInput{
		FindingID: "f1", Type: EvidenceTypeVerification,
		Request:        RequestEvidence{Method: "GET", URL: "http://h.test/p?q=1", Parameter: "q"},
		Response:       ResponseEvidence{StatusCode: 200, Excerpt: "ok"},
		Observation:    "context=html",
		Verification:   "reflected",
		Confidence:     0.9,
		DetectorFields: map[string]string{"b": "2", "a": "1"},
	}
}

// --- Hash tests (task section 38) -------------------------------------

func TestHash_SameEvidenceSameHash(t *testing.T) {
	a := sampleHashInput()
	b := sampleHashInput()
	if integrityHash(a) != integrityHash(b) {
		t.Error("identical canonical input produced different hashes")
	}
}

func TestHash_DifferentMapFieldOrderSameHash(t *testing.T) {
	a := sampleHashInput()
	a.DetectorFields = map[string]string{"a": "1", "b": "2"} // same content, different construction order
	b := sampleHashInput()
	b.DetectorFields = map[string]string{"b": "2", "a": "1"}
	if integrityHash(a) != integrityHash(b) {
		t.Error("map key construction order affected the hash -- encoding/json must sort map keys, but this proves it")
	}
}

func TestHash_ChangedEvidenceDifferentHash(t *testing.T) {
	a := sampleHashInput()
	b := sampleHashInput()
	b.Observation = "context=attribute"
	if integrityHash(a) == integrityHash(b) {
		t.Error("changed Observation must change the hash")
	}
}

func TestHash_ChangedConfidenceDifferentHash(t *testing.T) {
	a := sampleHashInput()
	b := sampleHashInput()
	b.Confidence = 0.5
	if integrityHash(a) == integrityHash(b) {
		t.Error("changed Confidence must change the hash")
	}
}

func TestHash_TimestampExcludedFromCanonicalInput(t *testing.T) {
	// canonicalHashInput has NO timestamp field at all -- verified here
	// by construction: two CanonicalEvidence items built at different
	// times, but otherwise identical, must hash identically.
	cf := fixtureXSS()
	itemsA := BuildEvidence(cf, DefaultLimits())
	time.Sleep(2 * time.Millisecond)
	itemsB := BuildEvidence(cf, DefaultLimits())

	if len(itemsA) != len(itemsB) {
		t.Fatalf("len mismatch: %d vs %d", len(itemsA), len(itemsB))
	}
	for i := range itemsA {
		if itemsA[i].CollectedAt.Equal(itemsB[i].CollectedAt) {
			t.Fatal("test setup bug: CollectedAt should differ between the two builds")
		}
		if itemsA[i].IntegrityHash != itemsB[i].IntegrityHash {
			t.Errorf("index %d: IntegrityHash differs despite only CollectedAt changing: %q vs %q", i, itemsA[i].IntegrityHash, itemsB[i].IntegrityHash)
		}
		if itemsA[i].EvidenceID != itemsB[i].EvidenceID {
			t.Errorf("index %d: EvidenceID differs despite only CollectedAt changing", i)
		}
	}
}

// --- Evidence ID tests (task section 17) --------------------------------

func TestEvidenceID_IsPrefixOfIntegrityHash(t *testing.T) {
	input := sampleHashInput()
	id := evidenceID(input)
	hash := integrityHash(input)
	if hash[:len(id)] != id {
		t.Errorf("EvidenceID %q is not a prefix of IntegrityHash %q", id, hash)
	}
}

func TestEvidenceID_Length(t *testing.T) {
	id := evidenceID(sampleHashInput())
	if len(id) != 32 {
		t.Errorf("len(EvidenceID) = %d, want 32", len(id))
	}
}

func TestEvidenceID_DuplicateContentSameID(t *testing.T) {
	a := evidenceID(sampleHashInput())
	b := evidenceID(sampleHashInput())
	if a != b {
		t.Error("identical canonical content must produce the identical EvidenceID (task section 17-18)")
	}
}

func TestEvidenceID_DifferentContentDifferentID(t *testing.T) {
	a := sampleHashInput()
	b := sampleHashInput()
	b.FindingID = "different-finding"
	if evidenceID(a) == evidenceID(b) {
		t.Error("different FindingID must produce a different EvidenceID")
	}
}
