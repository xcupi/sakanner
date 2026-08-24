// Package chains implements Phase 3.30's finding correlation and
// vulnerability chain foundation: an additive layer ABOVE detection
// that reads pkg/models.Finding values (the existing, unmodified
// detector contract every "-active"/legacy detector already produces)
// and produces typed, evidenced relationships between DIFFERENT
// findings, and candidate chains grouping related findings together.
//
// This is NOT internal/correlation (Phase 3.8) -- that package
// deduplicates multiple raw findings that represent the SAME
// underlying vulnerability into one CanonicalFinding. This package
// does the opposite: it relates DIFFERENT, already-distinct findings
// to each other. See docs/phase-3-30-correlation-chain-foundation.md
// section 5 for the full comparison and why internal/correlation is
// never modified or depended on by this package.
//
// No vulnerability detector is implemented or modified here. No
// finding's own Severity/Confidence is ever changed. A ChainCandidate
// is never marked CONFIRMED by this phase's own policy -- see
// candidate.go's own doc comment.
package chains

import "sakanner/pkg/models"

// RelationType is the fixed, closed set of relationship kinds this
// package can produce -- exactly the 9 named in
// docs/phase-3-30-correlation-chain-foundation.md's own "Relation
// types" section. Never extended by string concatenation or ad hoc
// values -- every RelationType a caller can observe is one of these
// constants.
type RelationType string

const (
	RelationSameEndpoint          RelationType = "SAME_ENDPOINT"
	RelationSameParameter         RelationType = "SAME_PARAMETER"
	RelationSameResource          RelationType = "SAME_RESOURCE"
	RelationSameIdentity          RelationType = "SAME_IDENTITY"
	RelationSameScan              RelationType = "SAME_SCAN"
	RelationSharedEvidence        RelationType = "SHARED_EVIDENCE"
	RelationDataFlow              RelationType = "DATA_FLOW"
	RelationPotentialPrecondition RelationType = "POTENTIAL_PRECONDITION"
	RelationPotentialImpactAmp    RelationType = "POTENTIAL_IMPACT_AMPLIFIER"
)

// ChainEvidenceKind names WHY one specific relation was recorded --
// never a bare "these look similar" heuristic; always a specific,
// checkable fact.
type ChainEvidenceKind string

const (
	// EvidenceSharedScan/SharedIdentity are the two structural
	// preconditions -- see relate.go's isolation gate.
	EvidenceSharedScan     ChainEvidenceKind = "shared_scan"
	EvidenceSharedIdentity ChainEvidenceKind = "shared_identity"
	// EvidenceSharedEndpoint/SharedParameter are structural facts about
	// the two findings' own fields.
	EvidenceSharedEndpoint  ChainEvidenceKind = "shared_endpoint"
	EvidenceSharedParameter ChainEvidenceKind = "shared_parameter"
	// EvidenceSharedResourceValue is a specific, identifier-shaped
	// value extracted from BOTH findings' own AffectedParameter/URL.
	EvidenceSharedResourceValue ChainEvidenceKind = "shared_resource_value"
	// EvidenceSubstringOverlap is a specific, non-trivial substring
	// present in both findings' own evidence content.
	EvidenceSubstringOverlap ChainEvidenceKind = "evidence_substring_overlap"
	// EvidenceValueFlowsInto is a specific, identifier-shaped value
	// that appears in one finding's OWN evidence content and is ALSO
	// the other finding's own identifying value (resource identifier
	// or host) -- the specific signal DATA_FLOW/POTENTIAL_PRECONDITION
	// relations require.
	EvidenceValueFlowsInto ChainEvidenceKind = "value_flows_into"
	// EvidenceStructuralAmplifier backs POTENTIAL_IMPACT_AMPLIFIER --
	// an existing structural relation (endpoint/resource) between two
	// DIFFERENT vulnerability types, at least one high/critical.
	EvidenceStructuralAmplifier ChainEvidenceKind = "structural_amplifier"
)

// ChainEvidence is one specific, checkable fact justifying a
// FindingRelation -- never free-form "similarity."
type ChainEvidence struct {
	Kind        ChainEvidenceKind `json:"kind"`
	Description string            `json:"description"`
	// Detail is the actual matched value(s) -- e.g. the shared
	// resource identifier's literal value, or the overlapping
	// substring itself -- so the relation is independently
	// re-checkable against the two findings' own recorded fields,
	// never merely asserted.
	Detail string `json:"detail"`
}

// FindingRelation is one typed, evidenced, pairwise relationship
// between exactly two findings. FindingAID/FindingBID are always
// stored in a fixed (lexically sorted) order so the SAME pair never
// produces two differently-ordered relation records.
type FindingRelation struct {
	ID         string          `json:"id"`
	Type       RelationType    `json:"type"`
	FindingAID string          `json:"finding_a_id"`
	FindingBID string          `json:"finding_b_id"`
	ScanJobID  string          `json:"scan_job_id"`
	Reason     string          `json:"reason"`
	Evidence   []ChainEvidence `json:"evidence,omitempty"`
	// Confidence is THIS RELATION's own confidence that the two
	// findings are genuinely related -- entirely separate from either
	// finding's own Confidence field, which this package never reads
	// as a correlation signal (task's own explicit prohibition) and
	// never writes to.
	Confidence float64 `json:"confidence"`
}

// ChainStatus is a ChainCandidate's own lifecycle/evidence-strength
// state -- deliberately separate from, and never influencing, any
// individual finding's own Severity/ValidationStatus.
type ChainStatus string

const (
	// ChainPotential: structural relations only (same scan/identity/
	// endpoint/parameter) -- a plausible grouping, no evidence-level
	// link between the findings' own content.
	ChainPotential ChainStatus = "POTENTIAL"
	// ChainSupported: at least one evidence-level relation
	// (DATA_FLOW/SHARED_EVIDENCE/POTENTIAL_PRECONDITION) backs the
	// grouping.
	ChainSupported ChainStatus = "SUPPORTED"
	// ChainConfirmed is defined for the model/type system and future
	// policy evolution, but this phase's own Correlate() NEVER assigns
	// it -- see candidate.go's own doc comment for why, and
	// docs/phase-3-30-acceptance-test.md's REMAINING LIMITATIONS.
	ChainConfirmed ChainStatus = "CONFIRMED"
)

// ChainCandidate is a set of 2+ findings, connected by one or more
// FindingRelations, with an explicit status/confidence/impact --
// always traceable back to its exact input FindingIDs/RelationIDs.
type ChainCandidate struct {
	ID        string `json:"id"`
	ScanJobID string `json:"scan_job_id"`
	// IdentityContext is the ONE identity every participating finding
	// shares (possibly "" for an unauthenticated scan) -- a
	// ChainCandidate can never span more than one, by construction
	// (see relate.go's isolation gate; this field simply surfaces what
	// every candidate already, structurally, satisfies).
	IdentityContext string      `json:"identity_context,omitempty"`
	FindingIDs      []string    `json:"finding_ids"`
	RelationIDs     []string    `json:"relation_ids"`
	Endpoints       []string    `json:"endpoints,omitempty"`
	Status          ChainStatus `json:"status"`
	// Confidence is a CHAIN-level value, entirely separate from any
	// participating finding's own Confidence.
	Confidence float64 `json:"confidence"`
	// ImpactEstimate is a short, bounded, human-readable description
	// of the chain's aggregate impact -- never a severity value, and
	// never written back onto any individual finding.
	ImpactEstimate  string   `json:"impact_estimate"`
	Reason          string   `json:"reason"`
	MissingEvidence []string `json:"missing_evidence,omitempty"`
}

// Result is Correlate's own output -- see engine.go.
type Result struct {
	Relations  []FindingRelation `json:"relations"`
	Candidates []ChainCandidate  `json:"candidates"`
	// Truncated is true if MaxFindings/MaxRelations/MaxCandidateChains
	// caused any input/output to be dropped -- see limits.go.
	Truncated bool `json:"truncated"`
}

// findingView is this package's own minimal, private projection of a
// models.Finding -- computed once per finding and reused across every
// pairwise comparison, rather than re-deriving the same facts
// (resource value, endpoint key, etc.) on every pair.
type findingView struct {
	finding  models.Finding
	scanID   string
	identity string
	endpoint string // Host + ":" + Port + AffectedEndpoint, normalized
	param    string
	resource string // extracted, identifier-shaped resource value, "" if none
}
