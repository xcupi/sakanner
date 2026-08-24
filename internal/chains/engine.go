// Package chains' public entry point. Correlate is a pure function --
// no package-level mutable state, no shared cache, nothing a
// concurrent caller could race on. Two calls with the same input
// (regardless of slice order) always produce byte-identical output
// (aside from map-derived intermediate state, which is always sorted
// before being returned -- see ordering.go). See
// docs/phase-3-30-correlation-chain-foundation.md for the full design.
package chains

import (
	"sort"

	"sakanner/pkg/models"
)

// Correlate computes FindingRelations and ChainCandidates from
// findings. It NEVER mutates any input models.Finding, never reads or
// writes any package-level state, and is safe to call concurrently
// from any number of goroutines with any inputs. A zero-value Limits{}
// is normalized to DefaultLimits(); pass DefaultLimits() explicitly
// (or a partially-overridden Limits) for production use.
func Correlate(findings []models.Finding, limits Limits) Result {
	limits = limits.normalize()

	views, order := buildViews(findings, limits)
	freq := tokenFrequency(views)

	var relations []FindingRelation
	truncated := len(findings) > limits.MaxFindings
	for i := 0; i < len(order) && len(relations) < limits.MaxRelations; i++ {
		for j := i + 1; j < len(order) && len(relations) < limits.MaxRelations; j++ {
			a, b := views[order[i]], views[order[j]]
			if !isolated(a, b) {
				continue
			}
			relations = append(relations, relationsFor(a, b, limits, freq)...)
			if len(relations) > limits.MaxRelations {
				relations = relations[:limits.MaxRelations]
				truncated = true
			}
		}
	}

	relations = dedupeRelations(relations)
	sortRelations(relations)

	candidates, candTruncated := buildCandidates(relations, views, limits)
	if candTruncated {
		truncated = true
	}

	return Result{Relations: relations, Candidates: candidates, Truncated: truncated}
}

// buildViews computes one findingView per input finding (deduplicated
// by Finding.ID, first occurrence wins -- a caller submitting the same
// finding twice must never double-count it), bounded to
// limits.MaxFindings via a DETERMINISTIC selection: sort by (ScanID,
// Host, AffectedEndpoint, ID) first, then keep the first N -- never an
// arbitrary/arrival-order-dependent subset. order is the resulting
// finding-ID list in that same deterministic order, which callers
// iterate over for pairwise comparison so relation-building itself
// never depends on map iteration.
func buildViews(findings []models.Finding, limits Limits) (map[string]findingView, []string) {
	dedup := make(map[string]models.Finding, len(findings))
	var order []string
	for _, f := range findings {
		if f.ID == "" {
			continue
		}
		if _, ok := dedup[f.ID]; ok {
			continue
		}
		dedup[f.ID] = f
		order = append(order, f.ID)
	}

	sort.Slice(order, func(i, j int) bool {
		a, b := dedup[order[i]], dedup[order[j]]
		if a.ScanID != b.ScanID {
			return a.ScanID < b.ScanID
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.AffectedEndpoint != b.AffectedEndpoint {
			return a.AffectedEndpoint < b.AffectedEndpoint
		}
		return a.ID < b.ID
	})
	if len(order) > limits.MaxFindings {
		order = order[:limits.MaxFindings]
	}

	views := make(map[string]findingView, len(order))
	for _, id := range order {
		f := dedup[id]
		res, _ := resourceValue(f)
		views[id] = findingView{
			finding:  f,
			scanID:   f.ScanID,
			identity: f.IdentityContext,
			endpoint: endpointKey(f),
			param:    f.AffectedParameter,
			resource: res,
		}
	}
	return views, order
}
