package correlation

import (
	"testing"

	"sakanner/pkg/models"
)

// Scan isolation tests (task section 29): findings from independent
// scans must never accidentally merge, even when everything else about
// them is identical.

func TestScanIsolation_IdenticalFindingTwoScansStaySeparate(t *testing.T) {
	e := NewEngine()
	e.Ingest(sqliFinding("scan-A", ""), sqliFinding("scan-B", ""))

	got := e.Findings()
	if len(got) != 2 {
		t.Fatalf("Findings() = %d, want 2 (identical finding, two independent scans)", len(got))
	}
	if got[0].ScanID == got[1].ScanID {
		t.Error("two findings from different scans must not report the same ScanID")
	}
	if got[0].FindingID == got[1].FindingID {
		t.Error("two findings from different scans must not share a FindingID")
	}
}

func TestScanIsolation_EvidenceNeverCrossesScans(t *testing.T) {
	a := sqliFinding("scan-A", "")
	a.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "scan-A-evidence")}
	b := sqliFinding("scan-B", "")
	b.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "scan-B-evidence")}

	e := NewEngine()
	e.Ingest(a, b)
	got := e.Findings()
	if len(got) != 2 {
		t.Fatalf("Findings() = %d, want 2", len(got))
	}
	for _, f := range got {
		if len(f.Evidence) != 1 {
			t.Errorf("scan %s: Evidence count = %d, want exactly 1 (its own only)", f.ScanID, len(f.Evidence))
		}
	}
}

func TestScanIsolation_RelationshipsNeverCrossScans(t *testing.T) {
	a := sqliFinding("scan-A", "")
	b := xssFinding("scan-B", "") // same host, different scan
	b.Host = a.Host

	e := NewEngine()
	e.Ingest(a, b)
	rels := Relationships(e.Findings())
	if len(rels) != 0 {
		t.Errorf("Relationships() = %+v, want none -- findings from different scans must never be related", rels)
	}
}
