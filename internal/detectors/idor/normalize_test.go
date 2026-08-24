package idor

import "testing"

func TestNormalizeBody_CollapsesDigitRuns(t *testing.T) {
	got := normalizeBody([]byte("request-id: 12345 at 2024-01-01T00:00:42Z"))
	want := "request-id: # at #-#-#T#:#:#Z"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

func TestLooksAllowed_2xxWithBody(t *testing.T) {
	if !looksAllowed(200, []byte(`{"id":"resource-a"}`)) {
		t.Error("looksAllowed(200, non-empty) = false, want true")
	}
}

func TestLooksAllowed_2xxEmptyBody(t *testing.T) {
	if looksAllowed(200, []byte("")) {
		t.Error("looksAllowed(200, empty) = true, want false")
	}
}

func TestLooksAllowed_4xxNeverAllowed(t *testing.T) {
	for _, code := range []int{401, 403, 404, 429} {
		if looksAllowed(code, []byte(`{"id":"resource-a"}`)) {
			t.Errorf("looksAllowed(%d, ...) = true, want false", code)
		}
	}
}

func TestLooksAllowed_5xxNeverAllowed(t *testing.T) {
	if looksAllowed(500, []byte(`{"id":"resource-a"}`)) {
		t.Error("looksAllowed(500, ...) = true, want false")
	}
}

func TestIsResourceSpecific_ContainsID(t *testing.T) {
	if !isResourceSpecific([]byte(`{"id":"resource-a","owner":"user-a"}`), "resource-a") {
		t.Error("isResourceSpecific = false, want true")
	}
}

func TestIsResourceSpecific_GenericBodyWithoutID(t *testing.T) {
	if isResourceSpecific([]byte(`{"status":"ok"}`), "resource-a") {
		t.Error("isResourceSpecific = true, want false -- the body never mentions the requested resource")
	}
}

func TestIsResourceSpecific_EmptyID(t *testing.T) {
	if isResourceSpecific([]byte(`{"id":"resource-a"}`), "") {
		t.Error("isResourceSpecific with an empty id = true, want false")
	}
}
