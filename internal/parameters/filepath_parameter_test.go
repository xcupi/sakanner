package parameters

import "testing"

func TestIsLikelyFilePathParameter_KnownNames_True(t *testing.T) {
	for _, name := range []string{
		"file", "filename", "filepath", "path", "file_path", "document",
		"document_path", "template", "resource", "download", "attachment",
		"image", "directory", "FILE", "Path",
	} {
		if !IsLikelyFilePathParameter(name) {
			t.Errorf("IsLikelyFilePathParameter(%q) = false, want true", name)
		}
	}
}

func TestIsLikelyFilePathParameter_NonFilePathNames_False(t *testing.T) {
	for _, name := range []string{
		"id", "page", "sort", "note_id", "url", "host", "cmd", "", "   ",
	} {
		if IsLikelyFilePathParameter(name) {
			t.Errorf("IsLikelyFilePathParameter(%q) = true, want false", name)
		}
	}
}

// TestIsLikelyFilePathParameter_PathInferredSuffixes_True proves the
// "_value"/"_id" suffix tolerance internal/parameters.InferPathInputs'
// own pathInputName convention requires (Phase 3.23), the same fix
// IsLikelyCommandParameter needed (Phase 3.26), applied here from the
// start.
func TestIsLikelyFilePathParameter_PathInferredSuffixes_True(t *testing.T) {
	for _, name := range []string{"file_value", "file_id", "download_value", "path_id"} {
		if !IsLikelyFilePathParameter(name) {
			t.Errorf("IsLikelyFilePathParameter(%q) = false, want true (path-inferred suffix form)", name)
		}
	}
}

func TestIsLikelyFilePathParameter_UnrelatedSuffixedNames_False(t *testing.T) {
	for _, name := range []string{"user_value", "category_id", "note_value"} {
		if IsLikelyFilePathParameter(name) {
			t.Errorf("IsLikelyFilePathParameter(%q) = true, want false (base name is not file-path-shaped)", name)
		}
	}
}
