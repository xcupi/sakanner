package correlation

import (
	"testing"

	"sakanner/pkg/models"
)

// --- Positive deduplication tests (task section 24) -----------------------

func TestDedup_ExactDuplicate(t *testing.T) {
	e := NewEngine()
	e.Ingest(xssFinding("scan-1", ""), xssFinding("scan-1", ""))

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() returned %d, want 1", len(got))
	}
}

func TestDedup_SameFindingDifferentProbe(t *testing.T) {
	e := NewEngine()
	e.Ingest(xssFinding("scan-1", "-probeA"), xssFinding("scan-1", "-probeB"))

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() returned %d, want 1 (same endpoint/parameter, different probe)", len(got))
	}
}

func TestDedup_SameFindingDifferentEvidence(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "evidence-A")}
	b := xssFinding("scan-1", "")
	b.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "evidence-B")}

	e := NewEngine()
	e.Ingest(a, b)

	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() returned %d, want 1", len(got))
	}
	if len(got[0].Evidence) != 2 {
		t.Errorf("Evidence count = %d, want 2 (both distinct evidence items merged)", len(got[0].Evidence))
	}
}

func TestDedup_URLHostnameCaseDifference(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Host = "Example.Test"
	b := xssFinding("scan-1", "")
	b.Host = "example.test"

	e := NewEngine()
	e.Ingest(a, b)

	if len(e.Findings()) != 1 {
		t.Fatalf("Findings() returned %d, want 1 (hostname case only)", len(e.Findings()))
	}
}

func TestDedup_DefaultPortDifference(t *testing.T) {
	a := sqliFinding("scan-1", "")
	a.URL, a.Host, a.Port = "https://example.test/products?id=1", "example.test", 443
	b := sqliFinding("scan-1", "")
	b.URL, b.Host, b.Port = "https://example.test:443/products?id=1", "example.test", 443

	e := NewEngine()
	e.Ingest(a, b)

	if len(e.Findings()) != 1 {
		t.Fatalf("Findings() returned %d, want 1 (explicit default port == omitted)", len(e.Findings()))
	}
}

func TestDedup_TrailingSlashNormalization(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/search"
	b := xssFinding("scan-1", "")
	b.AffectedEndpoint = "/search/"

	e := NewEngine()
	e.Ingest(a, b)

	if len(e.Findings()) != 1 {
		t.Fatalf("Findings() returned %d, want 1 (trailing slash only)", len(e.Findings()))
	}
}

func TestDedup_RepeatedScannerResult(t *testing.T) {
	e := NewEngine()
	f := sqliFinding("scan-1", "")
	for i := 0; i < 5; i++ {
		e.Ingest(f)
	}
	if len(e.Findings()) != 1 {
		t.Fatalf("Findings() returned %d, want 1 (5x repeated identical submission)", len(e.Findings()))
	}
}

func TestDedup_DuplicateDetectorOutput(t *testing.T) {
	// Two "different detector instances" (e.g. two Engine.Run passes)
	// producing the identical finding.
	e := NewEngine()
	e.Ingest(cmdInjectionFinding("scan-1", "tokenA"))
	e.Ingest(cmdInjectionFinding("scan-1", "tokenB"))

	if len(e.Findings()) != 1 {
		t.Fatalf("Findings() returned %d, want 1", len(e.Findings()))
	}
}

// --- Negative deduplication tests (task section 25) ------------------------

func TestNoMerge_XSSAndSQLi(t *testing.T) {
	e := NewEngine()
	xss := xssFinding("scan-1", "")
	xss.AffectedEndpoint, xss.AffectedParameter = "/search", "q"
	sqli := sqliFinding("scan-1", "")
	sqli.AffectedEndpoint, sqli.AffectedParameter = "/search", "q"
	sqli.Host = xss.Host

	e.Ingest(xss, sqli)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2 (XSS and SQLi must never merge)", len(e.Findings()))
	}
}

func TestNoMerge_SQLiAndSSRF(t *testing.T) {
	e := NewEngine()
	e.Ingest(sqliFinding("scan-1", ""), ssrfFinding("scan-1", "tok"))
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

func TestNoMerge_IDORAndPathTraversal(t *testing.T) {
	e := NewEngine()
	e.Ingest(idorFinding("scan-1", "resource-b"), traversalFinding("scan-1", "../protected/secret.txt"))
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

func TestNoMerge_DifferentEndpoints(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/search"
	b := xssFinding("scan-1", "")
	b.AffectedEndpoint = "/comments"

	e := NewEngine()
	e.Ingest(a, b)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

func TestNoMerge_DifferentParameters(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedParameter = "q"
	b := xssFinding("scan-1", "")
	b.AffectedParameter = "category"

	e := NewEngine()
	e.Ingest(a, b)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

func TestNoMerge_DifferentParameterLocations(t *testing.T) {
	a := xssFinding("scan-1", "")
	// b's AffectedParameter is not present in its own URL's query
	// string at all -- parameterLocation derives "unspecified" for it,
	// vs "query" for a.
	b := xssFinding("scan-1", "")
	b.AffectedParameter = "not_in_query_string"

	e := NewEngine()
	e.Ingest(a, b)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2 (query:q vs unspecified:not_in_query_string)", len(e.Findings()))
	}
}

func TestNoMerge_DifferentScanIDs(t *testing.T) {
	e := NewEngine()
	e.Ingest(xssFinding("scan-A", ""), xssFinding("scan-B", ""))
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2 (scan isolation)", len(e.Findings()))
	}
}

func TestNoMerge_DifferentResourcesWhereIdentityRequiresDistinction(t *testing.T) {
	e := NewEngine()
	e.Ingest(idorFinding("scan-1", "resource-b"), idorFinding("scan-1", "resource-c"))
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2 (different IDOR resource IDs)", len(e.Findings()))
	}
}

func TestNoMerge_DifferentHosts(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Host = "example.test"
	b := xssFinding("scan-1", "")
	b.Host = "other.test"

	e := NewEngine()
	e.Ingest(a, b)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

func TestNoMerge_DifferentSecurityRelevantPorts(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Port = 8080
	b := xssFinding("scan-1", "")
	b.Port = 9090

	e := NewEngine()
	e.Ingest(a, b)
	if len(e.Findings()) != 2 {
		t.Fatalf("Findings() returned %d, want 2", len(e.Findings()))
	}
}

// --- Detector independence (task section 5) --------------------------------

func TestEngine_AllSixDetectorTypesProduceCanonicalFindings(t *testing.T) {
	e := NewEngine()
	e.Ingest(
		xssFinding("scan-1", ""),
		sqliFinding("scan-1", ""),
		ssrfFinding("scan-1", "tok"),
		idorFinding("scan-1", "resource-b"),
		traversalFinding("scan-1", "../protected/secret.txt"),
		cmdInjectionFinding("scan-1", "tok"),
	)
	got := e.Findings()
	if len(got) != 6 {
		t.Fatalf("Findings() returned %d, want 6 (one per distinct vulnerability type)", len(got))
	}
	types := map[string]bool{}
	for _, f := range got {
		types[f.VulnerabilityType] = true
	}
	for _, want := range []string{"reflected_xss", "sql_injection", "ssrf", "idor", "path_traversal", "command_injection"} {
		if !types[want] {
			t.Errorf("missing canonical finding for vulnerability type %q", want)
		}
	}
}

func TestIngest_ReturnsPerInputStatus(t *testing.T) {
	e := NewEngine()
	results := e.Ingest(xssFinding("scan-1", "-a"), xssFinding("scan-1", "-b"))
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].Status != StatusNew {
		t.Errorf("results[0].Status = %q, want NEW (first time this identity was seen)", results[0].Status)
	}
	if results[1].Status != StatusDuplicate {
		t.Errorf("results[1].Status = %q, want DUPLICATE", results[1].Status)
	}
	if results[0].FindingID != results[1].FindingID {
		t.Error("both results must report the same FindingID -- they share an identity")
	}
}
