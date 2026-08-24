package parameters

import "testing"

func TestIsLikelyCommandParameter_KnownNames_True(t *testing.T) {
	for _, name := range []string{
		"host", "hostname", "ip", "address", "domain", "command", "cmd",
		"exec", "executable", "program", "file", "path", "target", "query",
		"HOST", "Cmd",
	} {
		if !IsLikelyCommandParameter(name) {
			t.Errorf("IsLikelyCommandParameter(%q) = false, want true", name)
		}
	}
}

func TestIsLikelyCommandParameter_NonCommandNames_False(t *testing.T) {
	for _, name := range []string{
		"id", "page", "sort", "note_id", "url", "", "   ",
	} {
		if IsLikelyCommandParameter(name) {
			t.Errorf("IsLikelyCommandParameter(%q) = true, want false", name)
		}
	}
}

// TestIsLikelyCommandParameter_PathInferredSuffixes_True proves the
// "_value"/"_id" suffix tolerance internal/parameters.InferPathInputs'
// own pathInputName convention requires (Phase 3.23) -- a
// command-shaped path segment is NEVER discovered as bare "host", only
// as "host_value"/"host_id".
func TestIsLikelyCommandParameter_PathInferredSuffixes_True(t *testing.T) {
	for _, name := range []string{"host_value", "host_id", "cmd_value", "exec_id"} {
		if !IsLikelyCommandParameter(name) {
			t.Errorf("IsLikelyCommandParameter(%q) = false, want true (path-inferred suffix form)", name)
		}
	}
}

func TestIsLikelyCommandParameter_UnrelatedSuffixedNames_False(t *testing.T) {
	// The suffix-stripping must not turn an UNRELATED base name into a
	// false positive -- only bases already in the allowlist qualify.
	for _, name := range []string{"user_value", "category_id", "note_value"} {
		if IsLikelyCommandParameter(name) {
			t.Errorf("IsLikelyCommandParameter(%q) = true, want false (base name is not command-shaped)", name)
		}
	}
}
