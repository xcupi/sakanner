package traversal

import "testing"

func TestNormalizeBody_CollapsesDigitRuns(t *testing.T) {
	got := normalizeBody([]byte("req-12345-done"))
	want := "req-#-done"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

func TestLooksAllowed_2xxWithBody(t *testing.T) {
	if !looksAllowed(200, []byte("content")) {
		t.Error("looksAllowed(200, non-empty) = false, want true")
	}
}

func TestLooksAllowed_2xxEmptyBody(t *testing.T) {
	if looksAllowed(200, []byte("")) {
		t.Error("looksAllowed(200, empty) = true, want false")
	}
}

func TestLooksAllowed_4xxNeverAllowed(t *testing.T) {
	if looksAllowed(403, []byte("forbidden")) {
		t.Error("looksAllowed(403, ...) = true, want false")
	}
	if looksAllowed(404, []byte("not found")) {
		t.Error("looksAllowed(404, ...) = true, want false")
	}
}

func TestLooksAllowed_5xxNeverAllowed(t *testing.T) {
	if looksAllowed(500, []byte("error")) {
		t.Error("looksAllowed(500, ...) = true, want false")
	}
}

func TestContainsMarker_Found(t *testing.T) {
	if !containsMarker([]byte("prefix PATH_TRAVERSAL_SECRET_MARKER suffix"), "PATH_TRAVERSAL_SECRET_MARKER") {
		t.Error("containsMarker = false, want true")
	}
}

func TestContainsMarker_NotFound(t *testing.T) {
	if containsMarker([]byte("nothing interesting here"), "PATH_TRAVERSAL_SECRET_MARKER") {
		t.Error("containsMarker = true, want false")
	}
}

func TestContainsMarker_EmptyMarkerNeverMatches(t *testing.T) {
	if containsMarker([]byte("anything at all"), "") {
		t.Error("containsMarker with an empty marker = true, want false -- an empty marker must never trivially match")
	}
}

func TestStripPayload_RemovesRawForm(t *testing.T) {
	got := stripPayload([]byte("Requested file: ../protected/secret.txt"), "../protected/secret.txt")
	want := "Requested file: "
	if string(got) != want {
		t.Errorf("stripPayload = %q, want %q", string(got), want)
	}
}

func TestStripPayload_RemovesURLEscapedForm(t *testing.T) {
	got := stripPayload([]byte("echo=..%2Fprotected%2Fsecret.txt"), "../protected/secret.txt")
	want := "echo="
	if string(got) != want {
		t.Errorf("stripPayload = %q, want %q", string(got), want)
	}
}

func TestStripPayload_EmptyPayloadNoOp(t *testing.T) {
	got := stripPayload([]byte("unchanged content"), "")
	if string(got) != "unchanged content" {
		t.Errorf("stripPayload with empty payload = %q, want unchanged", string(got))
	}
}
