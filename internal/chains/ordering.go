package chains

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// relationID returns a stable, content-derived ID for r -- the SAME
// (Type, FindingAID, FindingBID) triple always produces the IDENTICAL
// ID, mirroring internal/correlation.Identity.FindingID's own SHA-256
// content-hash precedent exactly (never a random UUID, never a
// counter). FindingAID/FindingBID are already sorted by newRelation
// before this is called, so the id is independent of which finding
// was passed as "a" vs "b".
func relationID(r FindingRelation) string {
	key := strings.Join([]string{string(r.Type), r.FindingAID, r.FindingBID}, "\x1f")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// candidateID returns a stable, content-derived ID for a chain
// candidate built from the given (already sorted) finding IDs.
func candidateID(findingIDs []string) string {
	key := strings.Join(findingIDs, "\x1f")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// dedupeRelations removes exact-duplicate (Type, FindingAID,
// FindingBID) entries -- task's own explicit "duplicate relation
// suppression" resource limit -- keeping the FIRST occurrence
// encountered in the caller's own already-deterministic pair order,
// never a random one.
func dedupeRelations(in []FindingRelation) []FindingRelation {
	seen := make(map[string]bool, len(in))
	out := make([]FindingRelation, 0, len(in))
	for _, r := range in {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out
}

// sortRelations imposes a total, content-derived order -- never map
// iteration or goroutine-completion order.
func sortRelations(rs []FindingRelation) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.FindingAID != b.FindingAID {
			return a.FindingAID < b.FindingAID
		}
		if a.FindingBID != b.FindingBID {
			return a.FindingBID < b.FindingBID
		}
		return a.ID < b.ID
	})
}

// sortCandidates imposes a total, content-derived order.
func sortCandidates(cs []ChainCandidate) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.ScanJobID != b.ScanJobID {
			return a.ScanJobID < b.ScanJobID
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return false
	})
}

// sortStrings is a small helper so callers never depend on map
// iteration order when turning a set into a slice.
func sortStrings(ss []string) []string {
	sort.Strings(ss)
	return ss
}
