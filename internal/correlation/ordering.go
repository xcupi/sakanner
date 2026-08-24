package correlation

import "sort"

// sortCanonicalFindings orders findings deterministically -- task
// section 22: normalized host, then port, then path, then
// vulnerability type, then parameter, then FindingID as the final,
// always-distinguishing tiebreak (FindingID is a content hash of the
// full identity, so two findings can share every other sort key only
// if they're genuinely different in ScanID/ParameterLocation/
// ResourceIdentifier -- components not otherwise part of the visible
// sort order -- making FindingID the only tiebreak that's always
// available and always sufficient).
func sortCanonicalFindings(findings []CanonicalFinding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Asset.Host != b.Asset.Host {
			return a.Asset.Host < b.Asset.Host
		}
		if a.Asset.Port != b.Asset.Port {
			return a.Asset.Port < b.Asset.Port
		}
		if a.Asset.Path != b.Asset.Path {
			return a.Asset.Path < b.Asset.Path
		}
		if a.VulnerabilityType != b.VulnerabilityType {
			return a.VulnerabilityType < b.VulnerabilityType
		}
		if a.HTTP.Parameter != b.HTTP.Parameter {
			return a.HTTP.Parameter < b.HTTP.Parameter
		}
		return a.FindingID < b.FindingID
	})
}
