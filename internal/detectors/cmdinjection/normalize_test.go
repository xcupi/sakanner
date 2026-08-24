package cmdinjection

import "testing"

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
	if looksAllowed(400, []byte("bad request")) {
		t.Error("looksAllowed(400, ...) = true, want false")
	}
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
