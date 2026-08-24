package parameters

import "testing"

func TestIsLikelyURLParameter_KnownNames_True(t *testing.T) {
	for _, name := range []string{
		"url", "uri", "link", "target", "destination", "dest",
		"redirect", "redirect_uri", "callback", "webhook", "endpoint",
		"image", "resource", "next", "return_url", "feed", "src", "href",
		"avatar", "imageUrl", "callback_url", "feedUri",
	} {
		if !IsLikelyURLParameter(name) {
			t.Errorf("IsLikelyURLParameter(%q) = false, want true", name)
		}
	}
}

func TestIsLikelyURLParameter_NonURLNames_False(t *testing.T) {
	for _, name := range []string{
		"id", "page", "sort", "order", "note_id", "user_id",
		"timestamp", "format", "", "   ",
	} {
		if IsLikelyURLParameter(name) {
			t.Errorf("IsLikelyURLParameter(%q) = true, want false", name)
		}
	}
}

// TestIsLikelyURLParameter_PathInferredSuffixes_True proves the Phase
// 3.28 fix: internal/parameters.InferPathInputs (Phase 3.23) always
// derives a path-location parameter's name as
// <preceding-segment>_value/_id, never a bare recognized name.
func TestIsLikelyURLParameter_PathInferredSuffixes_True(t *testing.T) {
	for _, name := range []string{"redirect_value", "next_value", "destination_value", "target_id"} {
		if !IsLikelyURLParameter(name) {
			t.Errorf("IsLikelyURLParameter(%q) = false, want true (path-inferred suffix)", name)
		}
	}
}

func TestIsLikelyURLParameter_UnrelatedSuffixedNames_False(t *testing.T) {
	for _, name := range []string{"note_value", "user_id", "note_id", "page_value"} {
		if IsLikelyURLParameter(name) {
			t.Errorf("IsLikelyURLParameter(%q) = true, want false (unrelated base name, suffix stripping must not loosen the allowlist)", name)
		}
	}
}
