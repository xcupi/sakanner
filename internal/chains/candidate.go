package chains

import (
	"fmt"
	"strings"
)

// disjointSet is a minimal, bounded union-find over finding IDs --
// the ONLY graph-expansion mechanism this package uses. It never
// recurses and never walks an edge list more than once per relation,
// so building candidates from R relations is O(R * alpha(N)), never
// unbounded.
type disjointSet struct {
	parent map[string]string
}

func newDisjointSet() *disjointSet {
	return &disjointSet{parent: make(map[string]string)}
}

func (d *disjointSet) find(x string) string {
	if _, ok := d.parent[x]; !ok {
		d.parent[x] = x
		return x
	}
	root := x
	for d.parent[root] != root {
		root = d.parent[root]
	}
	// Path compression, bounded by the same single pass.
	for d.parent[x] != root {
		next := d.parent[x]
		d.parent[x] = root
		x = next
	}
	return root
}

func (d *disjointSet) union(a, b string) {
	ra, rb := d.find(a), d.find(b)
	if ra != rb {
		d.parent[ra] = rb
	}
}

// buildCandidates groups relations' participating findings into
// connected components (via a bounded union-find, never recursive
// graph traversal) and builds one ChainCandidate per component with
// 2+ findings, capped at limits.MaxChainLength findings and
// limits.MaxCandidateChains total candidates -- both enforced
// deterministically (sorted order, never map iteration or arrival
// order). Every candidate remains fully traceable to its own
// FindingIDs/RelationIDs -- see model.go's own ChainCandidate doc
// comment.
func buildCandidates(relations []FindingRelation, views map[string]findingView, limits Limits) ([]ChainCandidate, bool) {
	if len(relations) == 0 {
		return nil, false
	}

	ds := newDisjointSet()
	for _, r := range relations {
		ds.union(r.FindingAID, r.FindingBID)
	}

	componentFindings := map[string][]string{} // root -> finding IDs
	componentRelations := map[string][]FindingRelation{}
	for _, r := range relations {
		root := ds.find(r.FindingAID)
		componentRelations[root] = append(componentRelations[root], r)
	}
	seenFinding := map[string]bool{}
	for _, r := range relations {
		for _, fid := range []string{r.FindingAID, r.FindingBID} {
			if seenFinding[fid] {
				continue
			}
			seenFinding[fid] = true
			root := ds.find(fid)
			componentFindings[root] = append(componentFindings[root], fid)
		}
	}

	roots := make([]string, 0, len(componentFindings))
	for root := range componentFindings {
		roots = append(roots, root)
	}
	sortStrings(roots)

	var candidates []ChainCandidate
	truncated := false
	for _, root := range roots {
		findingIDs := sortStrings(append([]string{}, componentFindings[root]...))
		capped := false
		if len(findingIDs) > limits.MaxChainLength {
			findingIDs = findingIDs[:limits.MaxChainLength]
			capped = true
			truncated = true
		}
		inSet := make(map[string]bool, len(findingIDs))
		for _, fid := range findingIDs {
			inSet[fid] = true
		}

		var relIDs []string
		var relTypes = map[RelationType]bool{}
		var endpoints = map[string]bool{}
		var vulnTypes = map[string]bool{}
		var identity string
		identitySet := false
		maxConfidence := 0.0
		for _, r := range componentRelations[root] {
			if !inSet[r.FindingAID] || !inSet[r.FindingBID] {
				continue // excluded by the MaxChainLength cap above
			}
			relIDs = append(relIDs, r.ID)
			relTypes[r.Type] = true
			if r.Confidence > maxConfidence {
				maxConfidence = r.Confidence
			}
		}
		if len(relIDs) == 0 {
			// Every relation touching this component was excluded by
			// the cap -- no candidate to report for it.
			continue
		}
		for _, fid := range findingIDs {
			v, ok := views[fid]
			if !ok {
				continue
			}
			if v.endpoint != "" {
				endpoints[v.endpoint] = true
			}
			vulnTypes[normalizeType(v.finding.VulnerabilityType)] = true
			if !identitySet {
				identity = v.identity
				identitySet = true
			}
		}

		status, missing := classifyStatus(relTypes)
		candidates = append(candidates, ChainCandidate{
			ID:              candidateID(findingIDs),
			ScanJobID:       views[findingIDs[0]].scanID,
			IdentityContext: identity,
			FindingIDs:      findingIDs,
			RelationIDs:     sortStrings(relIDs),
			Endpoints:       sortStrings(setKeys(endpoints)),
			Status:          status,
			Confidence:      maxConfidence,
			ImpactEstimate:  impactEstimate(len(findingIDs), len(vulnTypes), len(endpoints), capped),
			Reason:          reasonFor(relTypes),
			MissingEvidence: missing,
		})
	}

	sortCandidates(candidates)
	if len(candidates) > limits.MaxCandidateChains {
		candidates = candidates[:limits.MaxCandidateChains]
		truncated = true
	}
	return candidates, truncated
}

// classifyStatus applies this phase's own deterministic policy: any
// evidence-level relation type present promotes the chain to
// SUPPORTED; otherwise it stays POTENTIAL. CONFIRMED is never
// assigned -- see model.go's own ChainConfirmed doc comment.
func classifyStatus(types map[RelationType]bool) (ChainStatus, []string) {
	evidenceLevel := types[RelationDataFlow] || types[RelationSharedEvidence] || types[RelationPotentialPrecondition]
	if evidenceLevel {
		return ChainSupported, []string{
			"independent confirmation beyond the observed evidence-level relation(s) -- this phase's own policy never escalates a chain to CONFIRMED automatically",
		}
	}
	return ChainPotential, []string{
		"an evidence-level relation (DATA_FLOW, SHARED_EVIDENCE, or POTENTIAL_PRECONDITION) directly connecting the participating findings' own evidence content",
	}
}

func impactEstimate(findingCount, vulnTypeCount, endpointCount int, capped bool) string {
	s := fmt.Sprintf("%d participating finding(s) across %d distinct vulnerability type(s) and %d endpoint(s)", findingCount, vulnTypeCount, endpointCount)
	if capped {
		s += " (chain length capped by configured limits)"
	}
	return s
}

func reasonFor(types map[RelationType]bool) string {
	names := make([]string, 0, len(types))
	for t := range types {
		names = append(names, string(t))
	}
	names = sortStrings(names)
	return "connected via: " + strings.Join(names, ", ")
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
