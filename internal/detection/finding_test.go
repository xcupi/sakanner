package detection

import (
	"net"
	"testing"
	"time"

	"sakanner/pkg/models"
)

func TestNormalizeFinding_FillsMissingFields(t *testing.T) {
	d := stubDetector{id: "reflected-xss"}
	tgt := Target{
		ScanJobID: "job1", Host: "vuln.scanner.test", IP: net.ParseIP("127.0.0.21"), Port: 8080,
		URL: "http://vuln.scanner.test:8080/xss/reflected/vulnerable?q=x", Path: "/xss/reflected/vulnerable",
		Method: "GET", Parameter: "q",
	}
	now := time.Now().UTC()
	f := normalizeFinding(models.Finding{VulnerabilityType: "reflected_xss", Title: "Reflected XSS"}, d, tgt, now)

	if f.ID == "" {
		t.Error("ID was not filled in")
	}
	if f.ScanID != "job1" {
		t.Errorf("ScanID = %q, want job1", f.ScanID)
	}
	if f.DetectorID != "reflected-xss" {
		t.Errorf("DetectorID = %q, want reflected-xss", f.DetectorID)
	}
	if f.Host != "vuln.scanner.test" || f.Port != 8080 {
		t.Errorf("Host/Port = %q/%d, want vuln.scanner.test/8080", f.Host, f.Port)
	}
	if f.URL != tgt.URL {
		t.Errorf("URL = %q, want %q", f.URL, tgt.URL)
	}
	if f.Method != "GET" {
		t.Errorf("Method = %q, want GET", f.Method)
	}
	if f.AffectedEndpoint != "/xss/reflected/vulnerable" {
		t.Errorf("AffectedEndpoint = %q, want /xss/reflected/vulnerable", f.AffectedEndpoint)
	}
	if f.AffectedParameter != "q" {
		t.Errorf("AffectedParameter = %q, want q", f.AffectedParameter)
	}
	if f.ValidationStatus != models.ValidationStatusUnvalidated {
		t.Errorf("ValidationStatus = %q, want unvalidated", f.ValidationStatus)
	}
	if f.Source != "sakanner" {
		t.Errorf("Source = %q, want sakanner", f.Source)
	}
	if f.FirstSeen.IsZero() || f.LastSeen.IsZero() {
		t.Error("FirstSeen/LastSeen were not filled in")
	}
}

// TestNormalizeFinding_CopiesIdentityContextFromTarget is Phase
// 3.19's own requirement: a detector never sets IdentityContext
// itself -- normalizeFinding copies it automatically from the Target,
// for EVERY detector, not just an active one.
func TestNormalizeFinding_CopiesIdentityContextFromTarget(t *testing.T) {
	d := stubDetector{id: "sqli"}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a", IdentityContext: "account-a"}
	f := normalizeFinding(models.Finding{VulnerabilityType: "sql_injection"}, d, tgt, time.Now().UTC())
	if f.IdentityContext != "account-a" {
		t.Errorf("IdentityContext = %q, want account-a", f.IdentityContext)
	}
}

func TestNormalizeFinding_NoIdentityContext_StaysEmpty(t *testing.T) {
	d := stubDetector{id: "sqli"}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a"}
	f := normalizeFinding(models.Finding{VulnerabilityType: "sql_injection"}, d, tgt, time.Now().UTC())
	if f.IdentityContext != "" {
		t.Errorf("IdentityContext = %q, want empty for an unauthenticated target", f.IdentityContext)
	}
}

func TestNormalizeFinding_DetectorSetIdentityContext_NeverOverwritten(t *testing.T) {
	// Defensive: if a detector somehow already set IdentityContext
	// (never expected in practice -- section 3's own contract says a
	// detector must not manage identity state), normalizeFinding must
	// not silently overwrite it with a DIFFERENT target's value; this
	// mirrors every other "if f.X == \"\"" fill-in-only-if-missing
	// field in this same function.
	d := stubDetector{id: "sqli"}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a", IdentityContext: "account-b"}
	f := normalizeFinding(models.Finding{VulnerabilityType: "sql_injection", IdentityContext: "account-a"}, d, tgt, time.Now().UTC())
	if f.IdentityContext != "account-a" {
		t.Errorf("IdentityContext = %q, want the already-set account-a preserved, not overwritten by the target's account-b", f.IdentityContext)
	}
}

func TestNormalizeFinding_PreservesDetectorSetFields(t *testing.T) {
	d := stubDetector{id: "sqli"}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a"}
	explicitFirstSeen := time.Now().Add(-24 * time.Hour).UTC()

	f := normalizeFinding(models.Finding{
		VulnerabilityType: "sql_injection",
		Severity:          models.SeverityCritical,
		Confidence:        0.95,
		AffectedEndpoint:  "/custom-endpoint", // detector explicitly set this -- must not be overwritten by tgt.Path
		FirstSeen:         explicitFirstSeen,  // an existing finding being re-normalized on a later run
	}, d, tgt, time.Now().UTC())

	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity was overwritten: got %q, want critical", f.Severity)
	}
	if f.Confidence != 0.95 {
		t.Errorf("Confidence was overwritten: got %v, want 0.95", f.Confidence)
	}
	if f.AffectedEndpoint != "/custom-endpoint" {
		t.Errorf("AffectedEndpoint was overwritten: got %q, want /custom-endpoint", f.AffectedEndpoint)
	}
	if !f.FirstSeen.Equal(explicitFirstSeen) {
		t.Errorf("FirstSeen was overwritten: got %v, want %v", f.FirstSeen, explicitFirstSeen)
	}
}

func TestNormalizeFinding_DefaultSeverityFromMetadata(t *testing.T) {
	d := stubDetectorWithSeverity{id: "info-leak", severity: models.SeverityLow}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a"}

	f := normalizeFinding(models.Finding{VulnerabilityType: "info_leak"}, d, tgt, time.Now().UTC())
	if f.Severity != models.SeverityLow {
		t.Errorf("Severity = %q, want low (from Metadata().DefaultSeverity)", f.Severity)
	}
}

func TestNormalizeFinding_EvidenceGetsIDsAndFindingID(t *testing.T) {
	d := stubDetector{id: "x"}
	tgt := Target{ScanJobID: "job1", Host: "h", IP: net.ParseIP("127.0.0.1"), URL: "http://h/a", Path: "/a"}

	f := normalizeFinding(models.Finding{
		VulnerabilityType: "x",
		Evidence:          []models.Evidence{{Kind: models.EvidenceKindText, Content: "poc"}},
	}, d, tgt, time.Now().UTC())

	if len(f.Evidence) != 1 {
		t.Fatalf("Evidence = %+v, want 1 item", f.Evidence)
	}
	if f.Evidence[0].ID == "" {
		t.Error("Evidence[0].ID was not filled in")
	}
	if f.Evidence[0].FindingID != f.ID {
		t.Errorf("Evidence[0].FindingID = %q, want %q (the finding's own ID)", f.Evidence[0].FindingID, f.ID)
	}
}

func mkFinding(detectorID, host string, port int, endpoint, method, parameter, vulnType string) models.Finding {
	return models.Finding{
		ID: detectorID + "|" + host + "|" + endpoint, DetectorID: detectorID, Host: host, Port: port,
		AffectedEndpoint: endpoint, Method: method, AffectedParameter: parameter, VulnerabilityType: vulnType,
	}
}

func TestDeduplicate_RemovesExactRepeat(t *testing.T) {
	f1 := mkFinding("reflected-xss", "h", 80, "/search", "GET", "q", "reflected_xss")
	f2 := f1
	f2.ID = "different-id" // a detector re-reporting the same vulnerability is still a duplicate even with a fresh finding ID

	kept, dup := Deduplicate(nil, []models.Finding{f1, f2})
	if len(kept) != 1 {
		t.Fatalf("kept = %d findings, want 1", len(kept))
	}
	if dup != 1 {
		t.Errorf("duplicates = %d, want 1", dup)
	}
}

func TestDeduplicate_DifferentParameterIsNotADuplicate(t *testing.T) {
	f1 := mkFinding("reflected-xss", "h", 80, "/search", "GET", "q", "reflected_xss")
	f2 := mkFinding("reflected-xss", "h", 80, "/search", "GET", "category", "reflected_xss")

	kept, dup := Deduplicate(nil, []models.Finding{f1, f2})
	if len(kept) != 2 {
		t.Errorf("kept = %d findings, want 2 (different parameter is a distinct finding)", len(kept))
	}
	if dup != 0 {
		t.Errorf("duplicates = %d, want 0", dup)
	}
}

func TestDeduplicate_DifferentDetectorIsNotADuplicate(t *testing.T) {
	f1 := mkFinding("reflected-xss", "h", 80, "/search", "GET", "q", "reflected_xss")
	f2 := mkFinding("some-other-detector", "h", 80, "/search", "GET", "q", "reflected_xss")

	kept, dup := Deduplicate(nil, []models.Finding{f1, f2})
	if len(kept) != 2 {
		t.Errorf("kept = %d findings, want 2 (a different detector reporting the same shape is not a duplicate)", len(kept))
	}
	if dup != 0 {
		t.Errorf("duplicates = %d, want 0", dup)
	}
}

func TestDeduplicate_ConsultsExistingFindings(t *testing.T) {
	existing := []models.Finding{mkFinding("sqli", "h", 80, "/login", "GET", "id", "sql_injection")}
	fresh := mkFinding("sqli", "h", 80, "/login", "GET", "id", "sql_injection")
	fresh.ID = "fresh-run-id"

	kept, dup := Deduplicate(existing, []models.Finding{fresh})
	if len(kept) != 0 {
		t.Errorf("kept = %d findings, want 0 -- a finding already on record must not be re-created by a later run", len(kept))
	}
	if dup != 1 {
		t.Errorf("duplicates = %d, want 1", dup)
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []models.Finding{
		{ID: "1", Severity: models.SeverityHigh},
		{ID: "2", Severity: models.SeverityLow},
		{ID: "3", Severity: models.SeverityHigh},
	}
	got := FilterBySeverity(findings, models.SeverityHigh)
	if len(got) != 2 {
		t.Errorf("FilterBySeverity(high) = %d findings, want 2", len(got))
	}
}

func TestFilterByDetector(t *testing.T) {
	findings := []models.Finding{
		{ID: "1", DetectorID: "sqli"},
		{ID: "2", DetectorID: "reflected-xss"},
		{ID: "3", DetectorID: "sqli"},
	}
	got := FilterByDetector(findings, "sqli")
	if len(got) != 2 {
		t.Errorf("FilterByDetector(sqli) = %d findings, want 2", len(got))
	}
}
