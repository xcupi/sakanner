package chains

// Limits bounds every resource-sensitive dimension of Correlate --
// see docs/phase-3-30-correlation-chain-foundation.md's own "Resource
// limits" table for the rationale behind each default. A zero-value
// Limits is never used directly -- DefaultLimits() supplies sane
// defaults, and normalize() fills in any zero field a caller supplies
// via a partially-populated Limits.
type Limits struct {
	// MaxFindings bounds how many input findings are considered at
	// all. Findings beyond this are dropped, deterministically (see
	// engine.go), never randomly.
	MaxFindings int
	// MaxRelations bounds the total FindingRelation count. Pairwise
	// comparison stops once reached, in a fixed deterministic pair
	// order.
	MaxRelations int
	// MaxChainLength bounds how many findings one ChainCandidate may
	// ever contain.
	MaxChainLength int
	// MaxCandidateChains bounds the total ChainCandidate count
	// returned.
	MaxCandidateChains int
	// MaxEvidenceItemsPerRelation bounds how many ChainEvidence items
	// one FindingRelation may carry.
	MaxEvidenceItemsPerRelation int
}

// DefaultLimits returns the production-appropriate bounds documented
// in the architecture review.
func DefaultLimits() Limits {
	return Limits{
		MaxFindings:                 500,
		MaxRelations:                2000,
		MaxChainLength:              10,
		MaxCandidateChains:          100,
		MaxEvidenceItemsPerRelation: 5,
	}
}

// normalize fills in any zero field with DefaultLimits' own value --
// so a caller supplying a partial Limits{} (e.g. only overriding
// MaxFindings for a test) never accidentally gets an unbounded 0
// elsewhere.
func (l Limits) normalize() Limits {
	d := DefaultLimits()
	if l.MaxFindings <= 0 {
		l.MaxFindings = d.MaxFindings
	}
	if l.MaxRelations <= 0 {
		l.MaxRelations = d.MaxRelations
	}
	if l.MaxChainLength <= 0 {
		l.MaxChainLength = d.MaxChainLength
	}
	if l.MaxCandidateChains <= 0 {
		l.MaxCandidateChains = d.MaxCandidateChains
	}
	if l.MaxEvidenceItemsPerRelation <= 0 {
		l.MaxEvidenceItemsPerRelation = d.MaxEvidenceItemsPerRelation
	}
	return l
}
