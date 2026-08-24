package correlation

import (
	"fmt"
	"testing"

	"sakanner/pkg/models"
)

// --- Evidence merge tests (task section 26) ---------------------------------

func TestEvidenceMerge_TwoDistinctItemsBothRetained(t *testing.T) {
	a := sqliFinding("scan-1", "")
	a.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "Evidence 1")}
	b := sqliFinding("scan-1", "")
	b.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "Evidence 2")}

	e := NewEngine()
	e.Ingest(a, b)
	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
	if len(got[0].Evidence) != 2 {
		t.Fatalf("Evidence count = %d, want 2", len(got[0].Evidence))
	}
	contents := map[string]bool{}
	for _, ev := range got[0].Evidence {
		contents[ev.Content] = true
	}
	if !contents["Evidence 1"] || !contents["Evidence 2"] {
		t.Errorf("Evidence = %+v, want both Evidence 1 and Evidence 2 present", got[0].Evidence)
	}
}

func TestEvidenceMerge_RepeatedEvidenceAppearsOnce(t *testing.T) {
	a := sqliFinding("scan-1", "")
	a.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "Evidence 1")}
	b := sqliFinding("scan-1", "")
	b.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "Evidence 1")} // same content
	c := sqliFinding("scan-1", "")
	c.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "Evidence 1")} // repeat again

	e := NewEngine()
	e.Ingest(a, b, c)
	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
	if len(got[0].Evidence) != 1 {
		t.Errorf("Evidence count = %d, want 1 (repeated content must appear only once)", len(got[0].Evidence))
	}
}

func TestEvidenceMerge_DoesNotCreateOneFindingPerProbe(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 10; i++ {
		e.Ingest(xssFinding("scan-1", fmt.Sprintf("-probe%d", i)))
	}
	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1 (10 probes against the same endpoint/parameter)", len(got))
	}
}

// --- Evidence limits (task section 9) ---------------------------------------

func TestEvidenceLimit_BoundedItemCount(t *testing.T) {
	e := NewEngine()
	for i := 0; i < maxEvidenceGroupsPerFinding+20; i++ {
		f := sqliFinding("scan-1", "")
		f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, fmt.Sprintf("distinct-evidence-%d", i))}
		e.Ingest(f)
	}
	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
	if len(got[0].Evidence) > maxEvidenceItemsPerFinding {
		t.Errorf("Evidence count = %d, want <= %d", len(got[0].Evidence), maxEvidenceItemsPerFinding)
	}
}

func TestEvidenceLimit_ContentTruncated(t *testing.T) {
	huge := make([]byte, maxEvidenceContentBytes*4)
	for i := range huge {
		huge[i] = 'A'
	}
	f := sqliFinding("scan-1", "")
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, string(huge))}

	e := NewEngine()
	e.Ingest(f)
	got := e.Findings()
	if len(got[0].Evidence) != 1 {
		t.Fatalf("Evidence count = %d, want 1", len(got[0].Evidence))
	}
	if len(got[0].Evidence[0].Content) > maxEvidenceContentBytes {
		t.Errorf("Content length = %d, want <= %d", len(got[0].Evidence[0].Content), maxEvidenceContentBytes)
	}
}

func TestEvidenceLimit_StrongestRetainedDeterministically(t *testing.T) {
	// When forced to choose, longer (more detailed) evidence content is
	// kept over shorter content -- a fixed, documented, non-random rule.
	e := NewEngine()
	for i := 0; i < maxEvidenceGroupsPerFinding+10; i++ {
		f := sqliFinding("scan-1", "")
		// Later entries have progressively longer content.
		f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, fmt.Sprintf("evidence-%d-%s", i, repeatChar('X', i)))}
		e.Ingest(f)
	}
	got1 := e.Findings()
	got2 := e.Findings()
	if len(got1[0].Evidence) != len(got2[0].Evidence) {
		t.Fatal("repeated Findings() calls returned different evidence counts -- not deterministic")
	}
	for i := range got1[0].Evidence {
		if got1[0].Evidence[i] != got2[0].Evidence[i] {
			t.Fatalf("repeated Findings() calls returned different evidence at index %d -- not deterministic", i)
		}
	}
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
