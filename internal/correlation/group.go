package correlation

import (
	"sort"
	"strconv"
)

// Group is a VIEW over a canonical finding set -- task section 15's
// "finding groups": every finding sharing the same asset+endpoint,
// for callers that want to see "what's wrong with this endpoint" as a
// unit. A Group is never itself reported as a finding (it has no
// severity, confidence, or evidence of its own) and is never persisted
// by the Engine -- it is always recomputed from a CanonicalFinding
// slice on demand.
type Group struct {
	Host       string
	Port       int
	Path       string
	FindingIDs []string
}

// GroupByEndpoint groups findings by (host, port, path) -- task
// section 15's example (asset example.com, group
// https://example.com/api/search, containing both a Reflected XSS and
// a SQL Injection finding). Groups are returned in the same
// deterministic host/port/path order sortCanonicalFindings uses;
// FindingIDs within a group are sorted too, so GroupByEndpoint's
// output is deterministic for a given (already-deterministic) input
// slice regardless of input order.
func GroupByEndpoint(findings []CanonicalFinding) []Group {
	index := map[string]*Group{}
	var order []string
	for _, f := range findings {
		key := f.Asset.Host + "\x1f" + strconv.Itoa(f.Asset.Port) + "\x1f" + f.Asset.Path
		g, ok := index[key]
		if !ok {
			g = &Group{Host: f.Asset.Host, Port: f.Asset.Port, Path: f.Asset.Path}
			index[key] = g
			order = append(order, key)
		}
		g.FindingIDs = append(g.FindingIDs, f.FindingID)
	}
	sort.Strings(order)
	out := make([]Group, 0, len(order))
	for _, key := range order {
		g := index[key]
		sort.Strings(g.FindingIDs)
		out = append(out, *g)
	}
	return out
}
