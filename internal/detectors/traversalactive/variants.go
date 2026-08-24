package traversalactive

import "strings"

// wireVariants derives a small, fixed set of alternative WIRE
// representations of relPath -- explicitly NOT a large payload
// dictionary, mirroring internal/detectors/traversal's own private
// traversalVariants function exactly (raw, dot-encoded, slash-encoded,
// combined). For use ONLY with mutation.EncodingVerbatim against
// LocationQuery/LocationForm -- see rawPayload below for
// LocationPath/LocationJSON, which need the UNMODIFIED relPath
// instead (their own Mutate machinery applies exactly one correct
// escaping pass downstream; pre-encoding those two would double-encode,
// exactly the Phase 3.23 applyPath defect this avoids by construction).
func wireVariants(relPath string) []string {
	dotEncoded := strings.ReplaceAll(relPath, "..", "%2e%2e")
	slashEncoded := strings.ReplaceAll(relPath, "/", "%2F")
	combined := strings.ReplaceAll(slashEncoded, "..", "%2e%2e")

	seen := map[string]bool{}
	var variants []string
	for _, v := range []string{relPath, dotEncoded, slashEncoded, combined} {
		if seen[v] {
			continue
		}
		seen[v] = true
		variants = append(variants, v)
	}
	return variants
}

// rawPayload returns relPath unmodified -- the literal, un-pre-encoded
// representation LocationPath/LocationJSON need (see wireVariants'
// own doc comment for why).
func rawPayload(relPath string) string { return relPath }
