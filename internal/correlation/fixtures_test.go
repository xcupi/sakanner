package correlation

import (
	"fmt"
	"time"

	"sakanner/pkg/models"
)

// Synthetic finding fixtures for every detector this project has
// (task section 23) -- realistic field shapes matching what each real
// detector actually produces (see internal/detectors/*/detector.go's
// own finding() functions), but entirely synthetic data: no real
// target, no real host, no real payload beyond what each detector's
// own lab fixtures already use as synthetic markers.

func newEvidence(kind models.EvidenceKind, content string) models.Evidence {
	return models.Evidence{Kind: kind, Content: content}
}

// xssFinding mirrors internal/detectors/xssreflected's shape.
func xssFinding(scanID string, probeSuffix string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "xss-reflected",
		VulnerabilityType: "reflected_xss",
		Title:             "Reflected Cross-Site Scripting (XSS)",
		Severity:          models.SeverityHigh,
		Confidence:        0.9,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/search?q=sakannerXSSPROBE" + probeSuffix,
		Method:            "GET",
		AffectedEndpoint:  "/search",
		AffectedParameter: "q",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, `{"payload":"sakannerXSSPROBE`+probeSuffix+`","reflected":true}`),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// sqliFinding mirrors internal/detectors/sqli's shape.
func sqliFinding(scanID string, probeSuffix string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "sqli",
		VulnerabilityType: "sql_injection",
		Title:             "SQL Injection",
		Severity:          models.SeverityCritical,
		Confidence:        0.95,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/products?id=1" + probeSuffix,
		Method:            "GET",
		AffectedEndpoint:  "/products",
		AffectedParameter: "id",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, `{"error_family":"mysql","payload":"1`+probeSuffix+`"}`),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// ssrfFinding mirrors internal/detectors/ssrf's shape.
func ssrfFinding(scanID string, callbackToken string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "ssrf",
		VulnerabilityType: "ssrf",
		Title:             "Server-Side Request Forgery (SSRF)",
		Severity:          models.SeverityCritical,
		Confidence:        0.9,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/fetch?url=http://callback.test/cb/" + callbackToken,
		Method:            "GET",
		AffectedEndpoint:  "/fetch",
		AffectedParameter: "url",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, `{"callback_token":"`+callbackToken+`","callback_observed":true}`),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// idorFinding mirrors internal/detectors/idor's shape. resourceID is
// the resource identifier this finding's evidence concerns (section
// 19's "User A -> Resource B" distinction).
func idorFinding(scanID string, resourceID string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "idor",
		VulnerabilityType: "idor",
		Title:             "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)",
		Severity:          models.SeverityCritical,
		Confidence:        0.9,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/api/resource?resource_id=" + resourceID,
		Method:            "GET",
		AffectedEndpoint:  "/api/resource",
		AffectedParameter: "resource_id",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, fmt.Sprintf(`{"resource_id":%q,"proof_matches_owner_baseline":true}`, resourceID)),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// traversalFinding mirrors internal/detectors/traversal's shape.
// variant is the traversal representation used (probe-level
// difference, never part of identity -- section 19/20).
func traversalFinding(scanID string, variant string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "path-traversal",
		VulnerabilityType: "path_traversal",
		Title:             "Path Traversal",
		Severity:          models.SeverityCritical,
		Confidence:        0.9,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/files/download?file=" + variant,
		Method:            "GET",
		AffectedEndpoint:  "/files/download",
		AffectedParameter: "file",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, `{"variant":"`+variant+`","proof_marker_matched":true}`),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// cmdInjectionFinding mirrors internal/detectors/cmdinjection's shape.
// token is the per-probe correlation token (probe-level difference,
// never part of identity).
func cmdInjectionFinding(scanID string, token string) models.Finding {
	return models.Finding{
		ScanID:            scanID,
		DetectorID:        "command-injection",
		VulnerabilityType: "command_injection",
		Title:             "OS Command Injection",
		Severity:          models.SeverityCritical,
		Confidence:        0.95,
		Host:              "example.test",
		Port:              80,
		URL:               "http://example.test/api/ping?host=127.0.0.1",
		Method:            "GET",
		AffectedEndpoint:  "/api/ping",
		AffectedParameter: "host",
		ValidationStatus:  models.ValidationStatusUnvalidated,
		Source:            "sakanner",
		Evidence: []models.Evidence{
			newEvidence(models.EvidenceKindRequestResponse, `{"proof":"COMMAND_INJECTION_MARKER:`+token+`"}`),
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}
