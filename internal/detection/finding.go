package detection

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"sakanner/pkg/models"
)

// normalizeFinding fills in every field a Detector cannot reasonably be
// expected to set itself (ID, ScanID, DetectorID, Host/Port/URL/Method,
// Source, timestamps), while leaving whatever the detector already
// populated (VulnerabilityType, Title, Severity, Confidence,
// Evidence, ...) untouched -- this is the "Finding Normalization" stage
// between Detection and Deduplication in the framework's lifecycle.
func normalizeFinding(f models.Finding, d Detector, t Target, now time.Time) models.Finding {
	meta := d.Metadata()

	if f.ID == "" {
		f.ID = uuid.NewString()
	}
	f.ScanID = t.ScanJobID
	f.DetectorID = meta.ID
	if f.Target == "" {
		f.Target = t.Host
	}
	f.Host = t.Host
	f.Port = t.Port
	if f.URL == "" {
		f.URL = t.URL
	}
	if f.Method == "" {
		f.Method = t.Method
	}
	if f.AffectedEndpoint == "" {
		f.AffectedEndpoint = t.Path
	}
	if f.AffectedParameter == "" {
		f.AffectedParameter = t.Parameter
	}
	if f.Severity == "" {
		f.Severity = meta.DefaultSeverity
	}
	if f.ValidationStatus == "" {
		f.ValidationStatus = models.ValidationStatusUnvalidated
	}
	if f.Source == "" {
		f.Source = "sakanner"
	}
	// Phase 3.19: copied automatically for EVERY detector, not just an
	// active one -- a detector never sets this field itself (task
	// section 9's "IdentityContext must remain attached to... finding",
	// section 2's "Do NOT allow detectors to directly manage...
	// identity state").
	if f.IdentityContext == "" {
		f.IdentityContext = t.IdentityContext
	}
	for i := range f.Evidence {
		if f.Evidence[i].ID == "" {
			f.Evidence[i].ID = uuid.NewString()
		}
		f.Evidence[i].FindingID = f.ID
		if f.Evidence[i].CreatedAt.IsZero() {
			f.Evidence[i].CreatedAt = now
		}
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	f.LastSeen = now
	return f
}

// dedupKey identifies a Finding's identity for deduplication: the same
// detector reporting the same vulnerability type at the same
// host/port/URL/method/parameter is one finding, not several, no matter
// how many times a scan (or repeated scans against the same target)
// produces it. This mirrors lab/comparison.go's own matching key
// (VulnerabilityType + AffectedEndpoint) with the extra fields a real
// multi-host, multi-detector engine needs to stay precise -- see
// docs/phase-3-1-detection-engine.md "Deduplication" for the full
// rationale.
func dedupKey(f models.Finding) string {
	return strings.Join([]string{
		f.DetectorID, f.Host, strconv.Itoa(f.Port), f.AffectedEndpoint, f.Method, f.AffectedParameter, f.VulnerabilityType,
	}, "\x1f")
}

// Deduplicate returns findings with any entry sharing a dedupKey with an
// earlier one removed, keeping the first occurrence. existing (findings
// already on record for this scan job, e.g. from a prior Engine.Run
// against the same job) is consulted too, so re-running detection never
// re-creates a finding that's already persisted -- dedup is idempotent
// across runs, not just within one.
func Deduplicate(existing, findings []models.Finding) (kept []models.Finding, duplicates int) {
	seen := make(map[string]bool, len(existing)+len(findings))
	for _, f := range existing {
		seen[dedupKey(f)] = true
	}
	for _, f := range findings {
		key := dedupKey(f)
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		kept = append(kept, f)
	}
	return kept, duplicates
}

// FilterBySeverity returns the subset of findings at exactly severity.
func FilterBySeverity(findings []models.Finding, severity models.Severity) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}

// FilterByDetector returns the subset of findings produced by detectorID.
func FilterByDetector(findings []models.Finding, detectorID string) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if f.DetectorID == detectorID {
			out = append(out, f)
		}
	}
	return out
}
