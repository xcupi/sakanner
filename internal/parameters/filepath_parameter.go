package parameters

import "strings"

// filePathParameterFieldNames is an exact-match, case-insensitive list
// of common file/resource-path-reference parameter names --
// deliberately the SAME set internal/detectors/traversal's own private
// pathLikeParameterNames list already uses (file, filename, filepath,
// path, file_path, document, document_path, template, resource,
// download, attachment, image, directory), kept here instead so a
// future active detector never needs to duplicate or import it --
// mirroring IsLikelySecurityToken/IsLikelyObjectIdentifier/
// IsLikelyURLParameter/IsLikelyCommandParameter's own established
// precedent exactly.
var filePathParameterFieldNames = map[string]bool{
	"file": true, "filename": true, "filepath": true, "path": true,
	"file_path": true, "document": true, "document_path": true,
	"template": true, "resource": true, "download": true,
	"attachment": true, "image": true, "directory": true,
}

// IsLikelyFilePathParameter conservatively reports whether name looks
// like a parameter that reaches a file/resource-path lookup --
// name-based only, never derived from a field's discovered VALUE.
// Deliberately NOT named "IsLikelyPathParameter" -- that would be
// confusable with mutation.LocationPath, an unrelated "path" concept
// (a URL PATH SEGMENT, not a parameter whose VALUE looks like a
// file-system path). Used by
// internal/detectors/traversalactive.Eligible.
//
// A path-location parameter's NAME is never crawl-discovered verbatim
// -- internal/parameters.InferPathInputs (Phase 3.23) derives it from
// the preceding static path segment plus a fixed "_id"/"_value"
// suffix (see path.go's own pathInputName) -- this function strips
// those two known, conservative suffixes before the exact-match check
// (the same fix IsLikelyCommandParameter needed, Phase 3.26, applied
// here from the start rather than rediscovered a third time).
func IsLikelyFilePathParameter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if filePathParameterFieldNames[n] {
		return true
	}
	for _, suffix := range []string{"_value", "_id"} {
		if base, ok := strings.CutSuffix(n, suffix); ok && filePathParameterFieldNames[base] {
			return true
		}
	}
	return false
}
