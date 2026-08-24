package evidence

// Limits bounds evidence collection -- task section 20. Configurable
// (not hardcoded constants scattered through the package); DefaultLimits
// returns safe values every call site uses unless a caller explicitly
// overrides them.
type Limits struct {
	MaxEvidenceItemsPerFinding int
	MaxRequestBytes            int
	MaxResponseExcerptBytes    int
	MaxHeaderBytes             int
	MaxMetadataBytes           int
	MaxReproductionBytes       int
}

// DefaultLimits returns this package's safe defaults -- generous
// enough for any real finding this project's detectors produce (every
// evidence field they set is already far smaller than these ceilings,
// see each Phase 3.x detector's own maxBodySample/evidenceFragmentRadius
// bounds), small enough to make unbounded evidence growth structurally
// impossible regardless of what a malformed or adversarial
// CanonicalFinding contains.
func DefaultLimits() Limits {
	return Limits{
		MaxEvidenceItemsPerFinding: 20,
		MaxRequestBytes:            4096,
		MaxResponseExcerptBytes:    2048,
		MaxHeaderBytes:             2048,
		MaxMetadataBytes:           2048,
		MaxReproductionBytes:       2048,
	}
}

// truncate deterministically bounds s to at most max bytes, reporting
// whether truncation happened -- task section 6's "record: truncated =
// true." Truncation is always a plain byte-slice cut (never
// content-aware, never random), so the SAME input always truncates to
// the SAME output.
func truncate(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	return s[:max], true
}
