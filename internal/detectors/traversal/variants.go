package traversal

import "strings"

// traversalVariants derives a small, fixed set of alternative wire
// representations of relPath -- section 7's "small deterministic set,"
// explicitly NOT a large payload dictionary. Every variant decodes to
// the identical logical path; they differ only in how ".." and "/" are
// represented on the wire, exercising section 8's "URL encoding,
// normalized separators" requirement without combinatorial expansion.
//
// Callers must send these bytes RAW on the wire (see requestURL in
// detector.go) -- re-escaping a variant that already contains literal
// "%" characters would double-encode it and defeat the point of
// testing an encoded representation at all.
func traversalVariants(relPath string) []string {
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
