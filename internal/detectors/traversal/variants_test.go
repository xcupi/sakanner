package traversal

import "testing"

func TestTraversalVariants_GeneratesExpectedEncodings(t *testing.T) {
	variants := traversalVariants("../protected/secret-marker.txt")

	want := map[string]bool{
		"../protected/secret-marker.txt":         false, // raw
		"%2e%2e/protected/secret-marker.txt":     false, // dot-encoded
		"..%2Fprotected%2Fsecret-marker.txt":     false, // slash-encoded
		"%2e%2e%2Fprotected%2Fsecret-marker.txt": false, // combined
	}
	for _, v := range variants {
		if _, ok := want[v]; !ok {
			t.Errorf("unexpected variant %q", v)
			continue
		}
		want[v] = true
	}
	for v, found := range want {
		if !found {
			t.Errorf("expected variant %q not generated; got %v", v, variants)
		}
	}
}

func TestTraversalVariants_Deduplicated(t *testing.T) {
	// A relative path with no ".." or "/" collapses every variant to
	// the same string -- must be deduplicated to exactly 1, never
	// silently repeated (which would waste requests, section 22).
	variants := traversalVariants("secret.txt")
	if len(variants) != 1 {
		t.Errorf("traversalVariants(%q) = %v, want exactly 1 (all forms identical)", "secret.txt", variants)
	}
}

func TestTraversalVariants_SmallAndBounded(t *testing.T) {
	variants := traversalVariants("../../protected/secret-marker.txt")
	if len(variants) == 0 {
		t.Fatal("traversalVariants returned no variants")
	}
	if len(variants) > 4 {
		t.Errorf("traversalVariants returned %d variants, want at most 4 -- section 7 explicitly forbids a large payload dictionary", len(variants))
	}
}

func TestTraversalVariants_FirstIsAlwaysRaw(t *testing.T) {
	relPath := "../protected/secret-marker.txt"
	variants := traversalVariants(relPath)
	if variants[0] != relPath {
		t.Errorf("variants[0] = %q, want the raw, unencoded representation %q first", variants[0], relPath)
	}
}
