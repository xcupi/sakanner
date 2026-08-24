package correlation

// Relationship describes how two DISTINCT canonical findings relate --
// task section 14's "expose relationships... instead" of merging
// across vulnerability types. A Relationship never implies the two
// findings should be merged; SameAsset/SameEndpoint/SameParameter can
// all be true while FindingA and FindingB remain two separate,
// independently reported findings.
type Relationship struct {
	FindingA      string
	FindingB      string
	SameAsset     bool
	SameEndpoint  bool
	SameParameter bool
}

// Relationships computes every pairwise relationship among findings --
// task section 13's "identify findings that belong to the same scan/
// asset/endpoint/parameter while preserving distinct vulnerability
// types." Findings sharing an Identity are never passed in here as two
// separate entries (the Engine already merged them into one
// CanonicalFinding before this ever runs), so every pair considered is
// already known to be a genuinely distinct finding.
//
// Only pairs within the SAME scan are considered -- task section 16's
// scan isolation applies here too, not just to deduplication; a
// relationship between findings from two different scans would be
// exactly the kind of accidental cross-scan correlation section 16
// forbids.
//
// Returned in deterministic order: findings are first sorted (the same
// order Engine.Findings already returns), then pairs are emitted
// i<j over that order, so the result never depends on input slice
// order.
func Relationships(findings []CanonicalFinding) []Relationship {
	sorted := make([]CanonicalFinding, len(findings))
	copy(sorted, findings)
	sortCanonicalFindings(sorted)

	var out []Relationship
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			a, b := sorted[i], sorted[j]
			if a.ScanID != b.ScanID {
				continue
			}
			sameAsset := a.Asset.Host == b.Asset.Host && a.Asset.Port == b.Asset.Port
			sameEndpoint := sameAsset && a.Asset.Path == b.Asset.Path
			sameParameter := sameEndpoint && a.HTTP.Parameter == b.HTTP.Parameter
			if !sameAsset {
				continue
			}
			out = append(out, Relationship{
				FindingA:      a.FindingID,
				FindingB:      b.FindingID,
				SameAsset:     sameAsset,
				SameEndpoint:  sameEndpoint,
				SameParameter: sameParameter,
			})
		}
	}
	return out
}
