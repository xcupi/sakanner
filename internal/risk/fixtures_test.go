package risk

import (
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Synthetic canonical findings representing every combination task
// section 31 asks for -- entirely synthetic data, no real target, no
// new exploitation.

func canonicalFinding(scanID, findingID, vulnType string, sev models.Severity, confidence float64, status correlation.Status, host string) correlation.CanonicalFinding {
	return correlation.CanonicalFinding{
		FindingID:         findingID,
		ScanID:            scanID,
		DetectorID:        "synthetic",
		VulnerabilityType: vulnType,
		Title:             "Synthetic finding",
		Asset:             correlation.Asset{Scheme: "http", Host: host, Port: 80, Path: "/synthetic"},
		HTTP:              correlation.HTTPContext{Method: "GET", Parameter: "q", Location: "query"},
		Severity:          sev,
		Confidence:        confidence,
		Status:            status,
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}
}

// 1. LOW severity / LOW confidence / internal
func fixtureLowLowInternal() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-low-low-internal", "reflected_xss", models.SeverityLow, 0.2, correlation.StatusNew, "internal.test"),
		&AssetContext{Exposure: ExposureInternal}
}

// 2. MEDIUM severity / HIGH confidence / internal
func fixtureMediumHighInternal() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-medium-high-internal", "sql_injection", models.SeverityMedium, 0.9, correlation.StatusNew, "internal.test"),
		&AssetContext{Exposure: ExposureInternal}
}

// 3. HIGH severity / HIGH confidence / internet-facing
func fixtureHighHighInternetFacing() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-high-high-internet", "ssrf", models.SeverityHigh, 0.9, correlation.StatusNew, "public.test"),
		&AssetContext{Exposure: ExposureInternetFacing}
}

// 4. CRITICAL severity / HIGH confidence / internet-facing
func fixtureCriticalHighInternetFacing() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-critical-high-internet", "command_injection", models.SeverityCritical, 0.95, correlation.StatusNew, "public.test"),
		&AssetContext{Exposure: ExposureInternetFacing}
}

// 5. HIGH severity / LOW confidence / unknown exposure
func fixtureHighLowUnknown() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-high-low-unknown", "idor", models.SeverityHigh, 0.2, correlation.StatusNew, "unknown.test"), nil
}

// 6. MEDIUM severity / VERIFIED (2 independent evidence signatures) / internet-facing
func fixtureMediumVerifiedInternetFacing() (correlation.CanonicalFinding, *AssetContext) {
	return canonicalFinding("scan-1", "f-medium-verified-internet", "path_traversal", models.SeverityMedium, 0.55, correlation.StatusConfirmed, "public.test"),
		&AssetContext{Exposure: ExposureInternetFacing}
}
