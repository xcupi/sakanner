package chains

import (
	"strings"

	"sakanner/pkg/models"
)

// dataFlowSourceTypes are vulnerability types whose evidence can
// plausibly LEAK a value (an object identifier, a secret, an internal
// detail) that later flows into another finding's own identity --
// task's "information exposure -> object identifier -> authorization
// finding" scenario.
var dataFlowSourceTypes = map[string]bool{
	"info_exposure": true, "reflected_xss": true, "sqli": true,
	"path_traversal": true, "idor": true,
}

// preconditionSourceTypes are vulnerability types whose evidence
// names a DESTINATION (a host or endpoint) that reaching through them
// makes plausibly reachable -- task's "redirect behavior -> subsequent
// endpoint" and "SSRF -> internal resource" scenarios.
var preconditionSourceTypes = map[string]bool{
	"open_redirect": true, "ssrf": true,
}

// isolated reports whether a and b are allowed to be related AT ALL --
// the hard precondition every relation type below is gated behind.
// Both scan and identity must match exactly, including "" == "" for
// two unauthenticated findings -- but a non-empty identity NEVER
// matches a different (or empty) one. See
// docs/phase-3-30-correlation-chain-foundation.md's own "IDENTITY
// ISOLATION" section -- this is the phase's central safety property,
// checked before any relation-type-specific logic runs.
func isolated(a, b findingView) bool {
	if a.scanID == "" || b.scanID == "" || a.scanID != b.scanID {
		return false
	}
	return a.identity == b.identity
}

// relationsFor returns every relation this package's default policy
// recognizes between a and b, given isolated(a,b) already holds --
// callers (engine.go) are responsible for calling isolated first.
// freq is the whole-batch token frequency map (tokens.go's own
// tokenFrequency), used only by SHARED_EVIDENCE to reject
// detector-wide fixed constants.
func relationsFor(a, b findingView, limits Limits, freq map[string]int) []FindingRelation {
	if a.finding.ID == b.finding.ID {
		return nil
	}
	var out []FindingRelation

	sameEndpoint := a.endpoint != "" && a.endpoint == b.endpoint
	if sameEndpoint {
		out = append(out, newRelation(RelationSameEndpoint, a, b, 0.6,
			"both findings affect the same host/port/endpoint",
			ChainEvidence{Kind: EvidenceSharedEndpoint, Description: "identical endpoint", Detail: displayEndpoint(a.finding)},
		))
	}

	if a.param != "" && a.param == b.param {
		out = append(out, newRelation(RelationSameParameter, a, b, 0.3,
			"both findings affect a parameter with the same name (this alone does not imply the endpoints are related)",
			ChainEvidence{Kind: EvidenceSharedParameter, Description: "identical parameter name", Detail: a.param},
		))
	}

	sameResource := a.resource != "" && a.resource == b.resource
	if sameResource {
		out = append(out, newRelation(RelationSameResource, a, b, 0.7,
			"both findings identify the same resource value",
			ChainEvidence{Kind: EvidenceSharedResourceValue, Description: "identical resource identifier value", Detail: a.resource},
		))
	}

	if a.identity != "" && a.identity == b.identity {
		out = append(out, newRelation(RelationSameIdentity, a, b, 0.5,
			"both findings were produced under the same authenticated identity",
			ChainEvidence{Kind: EvidenceSharedIdentity, Description: "identical IdentityContext", Detail: a.identity},
		))
	}

	if tok, ok := substringOverlap(joinedEvidence(a.finding), joinedEvidence(b.finding), freq); ok {
		out = append(out, newRelation(RelationSharedEvidence, a, b, 0.5,
			"both findings' own evidence content shares a specific, non-trivial value",
			ChainEvidence{Kind: EvidenceSubstringOverlap, Description: "shared evidence substring", Detail: tok},
		))
	}

	if r, ok := dataFlowRelation(a, b); ok {
		out = append(out, r)
	}
	if r, ok := dataFlowRelation(b, a); ok {
		out = append(out, r)
	}

	if r, ok := preconditionRelation(a, b); ok {
		out = append(out, r)
	}
	if r, ok := preconditionRelation(b, a); ok {
		out = append(out, r)
	}

	if (sameEndpoint || sameResource) && a.finding.VulnerabilityType != b.finding.VulnerabilityType {
		if isHighOrCritical(a.finding.Severity) || isHighOrCritical(b.finding.Severity) {
			basis := "endpoint"
			if !sameEndpoint {
				basis = "resource"
			}
			out = append(out, newRelation(RelationPotentialImpactAmp, a, b, 0.4,
				"a high/critical-severity finding shares a structural relation (same "+basis+") with a different vulnerability type -- their COMBINED impact may exceed either finding alone, though this is not itself proof of a causal chain",
				ChainEvidence{Kind: EvidenceStructuralAmplifier, Description: "structural relation (" + basis + ") between different vulnerability classes, at least one high/critical severity", Detail: basis},
			))
		}
	}

	for i := range out {
		if len(out[i].Evidence) > limits.MaxEvidenceItemsPerRelation {
			out[i].Evidence = out[i].Evidence[:limits.MaxEvidenceItemsPerRelation]
		}
	}
	return out
}

// dataFlowRelation checks whether src's OWN evidence content contains
// dst's own identifying value (resource identifier) -- task's
// "information exposure -> object identifier -> authorization
// finding" scenario. Only considered when src's vulnerability type is
// a plausible data-revealing source (dataFlowSourceTypes) and the
// matched value is identifier-shaped (never a bare short string).
func dataFlowRelation(src, dst findingView) (FindingRelation, bool) {
	if !dataFlowSourceTypes[normalizeType(src.finding.VulnerabilityType)] {
		return FindingRelation{}, false
	}
	if dst.resource == "" {
		return FindingRelation{}, false
	}
	for _, content := range evidenceStrings(src.finding) {
		if strings.Contains(content, dst.resource) {
			return newRelation(RelationDataFlow, src, dst, 0.65,
				"the source finding's own evidence contains a value that is the destination finding's own resource identifier -- data discovered by the source may flow into the destination",
				ChainEvidence{Kind: EvidenceValueFlowsInto, Description: "source evidence contains destination's resource identifier", Detail: dst.resource},
			), true
		}
	}
	return FindingRelation{}, false
}

// preconditionRelation checks whether src's OWN evidence content
// names dst's own host (or a distinctive, identifier-shaped endpoint
// segment) -- task's "redirect behavior -> subsequent endpoint" and
// "SSRF -> internal resource" scenarios. Only considered when src's
// vulnerability type is a plausible destination-naming source
// (preconditionSourceTypes).
func preconditionRelation(src, dst findingView) (FindingRelation, bool) {
	if !preconditionSourceTypes[normalizeType(src.finding.VulnerabilityType)] {
		return FindingRelation{}, false
	}
	host := strings.ToLower(strings.TrimSpace(dst.finding.Host))
	if host == "" || len(host) < minTokenLength {
		return FindingRelation{}, false
	}
	// The destination's own host must differ from the source's own
	// host -- "src's evidence mentions ITS OWN target" is not a
	// precondition relation, only "src's evidence reaches somewhere
	// ELSE that dst also targets" is.
	if host == strings.ToLower(strings.TrimSpace(src.finding.Host)) {
		return FindingRelation{}, false
	}
	for _, content := range evidenceStrings(src.finding) {
		if strings.Contains(strings.ToLower(content), host) {
			return newRelation(RelationPotentialPrecondition, src, dst, 0.55,
				"the source finding's own evidence references the destination finding's own host -- reaching through the source may be a precondition for reaching the destination",
				ChainEvidence{Kind: EvidenceValueFlowsInto, Description: "source evidence references destination's own host", Detail: host},
			), true
		}
	}
	return FindingRelation{}, false
}

func isHighOrCritical(s models.Severity) bool {
	return s == models.SeverityHigh || s == models.SeverityCritical
}

func joinedEvidence(f models.Finding) string {
	return strings.Join(evidenceStrings(f), "\n")
}

func normalizeType(t string) string {
	return strings.ToLower(strings.TrimSpace(t))
}

// newRelation builds a FindingRelation with FindingAID/FindingBID in a
// FIXED, lexically-sorted order regardless of which of a/b was passed
// first -- the same finding pair must always produce byte-identical
// relation records, never order-dependent ones.
func newRelation(t RelationType, a, b findingView, confidence float64, reason string, evidence ...ChainEvidence) FindingRelation {
	idA, idB := a.finding.ID, b.finding.ID
	if idB < idA {
		idA, idB = idB, idA
	}
	r := FindingRelation{
		Type:       t,
		FindingAID: idA,
		FindingBID: idB,
		ScanJobID:  a.scanID,
		Reason:     reason,
		Evidence:   evidence,
		Confidence: confidence,
	}
	r.ID = relationID(r)
	return r
}
