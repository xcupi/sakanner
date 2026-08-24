package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestModelsJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	finding := Finding{
		ID:                "f1",
		ScanID:            "s1",
		Target:            "example.com",
		Asset:             "www.example.com",
		VulnerabilityType: "reflected-xss",
		Title:             "Reflected XSS in q parameter",
		Description:       "desc",
		Severity:          SeverityHigh,
		Confidence:        0.9,
		AffectedEndpoint:  "/search",
		AffectedParameter: "q",
		DetectionMethod:   "pattern-match",
		ValidationStatus:  ValidationStatusConfirmed,
		Evidence: []Evidence{
			{ID: "e1", FindingID: "f1", Kind: EvidenceKindRequestResponse, Content: "raw", CreatedAt: now},
		},
		Remediation: "sanitize input",
		References:  []string{"https://owasp.org/xss"},
		FirstSeen:   now,
		LastSeen:    now,
	}

	job := ScanJob{
		ID:            "s1",
		TargetIDs:     []string{"t1"},
		Status:        ScanJobStatusCompleted,
		ScopeSnapshot: []ScopeRule{{ID: "r1", Value: "example.com", Type: ScopeRuleDomainSuffix, Action: ScopeActionAllow, CreatedAt: now}},
		StartedAt:     now,
		CreatedAt:     now,
	}

	for name, v := range map[string]any{"finding": finding, "job": job} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s: empty json", name)
		}
	}

	var gotFinding Finding
	b, _ := json.Marshal(finding)
	if err := json.Unmarshal(b, &gotFinding); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if gotFinding.ID != finding.ID || gotFinding.Severity != finding.Severity {
		t.Fatalf("round trip mismatch: got %+v want %+v", gotFinding, finding)
	}
	if len(gotFinding.Evidence) != 1 || gotFinding.Evidence[0].Kind != EvidenceKindRequestResponse {
		t.Fatalf("evidence round trip mismatch: %+v", gotFinding.Evidence)
	}
}
