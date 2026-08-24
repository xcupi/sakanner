package evidence

import (
	"encoding/json"
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Synthetic finding fixtures mirroring every real detector's actual
// evidence shape (task section 42) -- entirely synthetic data, no real
// target, no new exploitation.

func rawJSON(raw rawRequestResponseEvidence) string {
	b, _ := json.Marshal(raw)
	return string(b)
}

func findingWith(vulnType, host, path, param string, sev models.Severity, confidence float64, raw rawRequestResponseEvidence) correlation.CanonicalFinding {
	return correlation.CanonicalFinding{
		FindingID:         "finding-" + vulnType,
		ScanID:            "scan-1",
		DetectorID:        vulnType,
		VulnerabilityType: vulnType,
		Title:             "Synthetic " + vulnType,
		Asset:             correlation.Asset{Scheme: "http", Host: host, Port: 80, Path: path},
		HTTP:              correlation.HTTPContext{Method: "GET", Parameter: param, Location: "query"},
		Severity:          sev,
		Confidence:        confidence,
		Status:            correlation.StatusNew,
		Evidence:          []correlation.EvidenceItem{{Kind: models.EvidenceKindRequestResponse, Content: rawJSON(raw)}},
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}
}

func fixtureXSS() correlation.CanonicalFinding {
	return findingWith("reflected_xss", "example.test", "/search", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{
		Request: "GET http://example.test/search?q=sakannerXSSPROBE123", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "text/html"},
		ResponseFragment: "<div>results for sakannerXSSPROBE123</div>", Parameter: "q", Payload: "sakannerXSSPROBE123",
		Observation: "context=html", Reason: "the payload was reflected unescaped in an HTML text context",
	})
}

func fixtureSQLi() correlation.CanonicalFinding {
	return findingWith("sql_injection", "example.test", "/products", "id", models.SeverityCritical, 0.95, rawRequestResponseEvidence{
		Request: "GET http://example.test/products?id=1%27", Response: "HTTP 500", StatusCode: 500,
		Headers:          map[string]string{"Content-Type": "text/plain"},
		ResponseFragment: "you have an error in your sql syntax near '''", Parameter: "id", Payload: "1'",
		Observation: `error_family="mysql" boolean_differential=true`, Reason: "a database-family-specific error signature was observed",
	})
}

func fixtureSSRF() correlation.CanonicalFinding {
	return findingWith("ssrf", "example.test", "/fetch", "url", models.SeverityCritical, 0.9, rawRequestResponseEvidence{
		Request: "GET http://example.test/fetch?url=http://callback.test/cb/tok-abc123", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "text/plain"},
		ResponseFragment: "fetched http://callback.test/cb/tok-abc123: ok", Parameter: "url", Payload: "http://callback.test/cb/tok-abc123",
		Observation: `callback_token=tok-abc123 callback_observed=true`, Reason: "the callback service observed a request scoped to this exact probe's token",
	})
}

func fixtureIDOR() correlation.CanonicalFinding {
	return findingWith("idor", "example.test", "/api/resource", "resource_id", models.SeverityCritical, 0.9, rawRequestResponseEvidence{
		Request: "GET http://example.test/api/resource?resource_id=resource-a (as user-b)", Response: "owner(user-a)=200 cross(user-b)=200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "application/json", "X-Test-Auth-User": "user-b"},
		ResponseFragment: `{"id":"resource-a","owner":"user-a","marker":"SECRET_MARKER_resource-a"}`, Parameter: "resource_id", Payload: "resource-a",
		Observation: `who=user-b what=resource-a owner=user-a expected=denied actual=200 proof_matches_owner_baseline=true`,
		Reason:      "authorization context(s) user-b received the SAME response that owner user-a receives",
	})
}

func fixtureTraversal() correlation.CanonicalFinding {
	return findingWith("path_traversal", "example.test", "/files/download", "file", models.SeverityCritical, 0.9, rawRequestResponseEvidence{
		Request: "GET http://example.test/files/download?file=../protected/secret-marker.txt (parameter=file, probe=semicolon)", Response: "status=200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "text/plain"},
		ResponseFragment: "PATH_TRAVERSAL_SECRET_MARKER", Parameter: "file", Payload: "../protected/secret-marker.txt",
		Observation: `target=/files/download parameter=file original=index.html probe=../protected/secret-marker.txt expected=denied actual=200 proof_marker_matched=true`,
		Reason:      "the response contains the exact constant marker prefix",
	})
}

func fixtureCommandInjection() correlation.CanonicalFinding {
	return findingWith("command_injection", "example.test", "/api/ping", "host", models.SeverityCritical, 0.95, rawRequestResponseEvidence{
		Request: "GET http://example.test/api/ping?host=%3Bsakanner_lab_echo%20tok-xyz789 (parameter=host, probe=semicolon (percent-encoded))", Response: "status=200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "text/plain"},
		ResponseFragment: "PING normal\nCOMMAND_INJECTION_MARKER:tok-xyz789", Parameter: "host", Payload: "%3Bsakanner_lab_echo%20tok-xyz789",
		Observation: `target=/api/ping parameter=host probe=semicolon (percent-encoded) expected=input_treated_as_data actual=controlled_command_execution_occurred proof=COMMAND_INJECTION_MARKER:tok-xyz789`,
		Reason:      "the response contains the exact constant marker prefix immediately followed by this probe's own token",
	})
}

// allSixFixtures returns all 6 vulnerability class fixtures -- task
// section 42/44.
func allSixFixtures() map[string]correlation.CanonicalFinding {
	return map[string]correlation.CanonicalFinding{
		"reflected_xss":     fixtureXSS(),
		"sql_injection":     fixtureSQLi(),
		"ssrf":              fixtureSSRF(),
		"idor":              fixtureIDOR(),
		"path_traversal":    fixtureTraversal(),
		"command_injection": fixtureCommandInjection(),
	}
}
