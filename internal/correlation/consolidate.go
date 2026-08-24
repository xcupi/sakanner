package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"sakanner/pkg/models"
)

// severityRank orders pkg/models.Severity without inventing a new risk
// model (task section 11: "do not create a new risk scoring system") --
// this is purely an ordinal comparator over the 5 values the existing
// model already defines.
var severityRank = map[models.Severity]int{
	models.SeverityInfo:     0,
	models.SeverityLow:      1,
	models.SeverityMedium:   2,
	models.SeverityHigh:     3,
	models.SeverityCritical: 4,
}

func rankOfSeverity(s models.Severity) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1 // an unrecognized value never outranks a recognized one
}

func maxSeverity(a, b models.Severity) models.Severity {
	if rankOfSeverity(b) > rankOfSeverity(a) {
		return b
	}
	return a
}

// minSeverity returns the lower-ranked of a and b -- EXCEPT that an
// unrecognized severity value (rankOfSeverity == -1) never wins,
// regardless of which side it's on. Without this guard, an
// unrecognized/garbage severity string would sort BELOW every real
// value (rank -1 is the numeric minimum) and incorrectly override a
// legitimate "critical" claim within the same evidence-signature group
// -- exactly the "conflicting severity" security scenario task section
// 30 requires the engine to handle safely: malformed input must never
// be able to suppress a real finding's severity. See
// TestSecurity_ConflictingSeverityAcrossResubmissions_NoCrash.
func minSeverity(a, b models.Severity) models.Severity {
	ra, rb := rankOfSeverity(a), rankOfSeverity(b)
	if ra < 0 {
		return b
	}
	if rb < 0 {
		return a
	}
	if rb < ra {
		return b
	}
	return a
}

// confidenceTier buckets a raw float64 confidence into the LOW/
// MEDIUM/HIGH categories task sections 10, 17, and 27 reason about --
// the underlying stored value stays the original float (task section
// 10: reuse what exists, do not invent a new system); this bucketing
// exists only so tests and documentation can talk about "LOW+MEDIUM"
// the way the task itself does. Thresholds match how every detector in
// this project already assigns confidence in practice (0.9-0.95 for a
// confirmed/HIGH-tier result, 0.55 for a MEDIUM-tier result, nothing
// below that today) -- see docs/phase-3-8-finding-correlation.md
// "Confidence consolidation."
func confidenceTier(c float64) string {
	switch {
	case c >= 0.75:
		return "HIGH"
	case c >= 0.4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// evidenceSignature returns a deterministic, content-addressed
// identifier for f's ENTIRE evidence set -- order-independent (sorted
// before hashing) and blind to per-record bookkeeping (Evidence.ID/
// FindingID/CreatedAt), so two findings carrying byte-for-byte
// identical evidence content always produce the same signature
// regardless of arrival order or when each was recorded. This is the
// unit "repeated identical evidence" (task sections 10, 27, 28) is
// measured against -- see "Confidence consolidation" in
// docs/phase-3-8-finding-correlation.md for the full two-level
// (min-within-signature, max-across-signatures) consolidation rule
// this enables.
func evidenceSignature(evidence []models.Evidence) string {
	parts := make([]string, len(evidence))
	for i, e := range evidence {
		parts[i] = string(e.Kind) + "\x1f" + e.Content
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return hex.EncodeToString(sum[:])
}

// evidenceItemsOf converts f.Evidence into this package's deduplicated
// EvidenceItem shape, sorted deterministically (Kind, then Content) so
// two findings with the same evidence CONTENT in different slice order
// still produce an identically-ordered EvidenceItem list.
func evidenceItemsOf(evidence []models.Evidence) []EvidenceItem {
	items := make([]EvidenceItem, len(evidence))
	for i, e := range evidence {
		items[i] = EvidenceItem{Kind: e.Kind, Content: e.Content}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Content < items[j].Content
	})
	return items
}
