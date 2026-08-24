package ssrf

import "testing"

func TestNormalizeBody_CollapsesDigitRuns(t *testing.T) {
	got := normalizeBody([]byte("request-id: 12345 at 2024-01-01T00:00:42Z"))
	want := "request-id: # at #-#-#T#:#:#Z"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

func TestNormalizeBody_PreservesNonDigitContent(t *testing.T) {
	got := normalizeBody([]byte("status: pending"))
	if got != "status: pending" {
		t.Errorf("normalizeBody = %q, want unchanged", got)
	}
}

func TestStripPayload_RemovesRawOccurrence(t *testing.T) {
	got := stripPayload([]byte("echo: http://callback.test/cb/abc"), "http://callback.test/cb/abc")
	if string(got) != "echo: " {
		t.Errorf("stripPayload = %q, want \"echo: \"", got)
	}
}

func TestStripPayload_RemovesHTMLEscapedOccurrence(t *testing.T) {
	payload := `http://callback.test/cb/abc?x=1&y=2`
	body := []byte("echo: http://callback.test/cb/abc?x=1&amp;y=2")
	got := stripPayload(body, payload)
	if string(got) != "echo: " {
		t.Errorf("stripPayload = %q, want \"echo: \"", got)
	}
}

func TestStripPayload_LeavesUnrelatedContentUntouched(t *testing.T) {
	got := stripPayload([]byte("results: alice, bob, admin"), "http://callback.test/cb/abc")
	if string(got) != "results: alice, bob, admin" {
		t.Errorf("stripPayload = %q, want unchanged", got)
	}
}

func TestContainsFetchErrorPhrase_Positive(t *testing.T) {
	for _, body := range []string{
		"fetch failed: connection refused",
		"Error: could not resolve host",
		"dial tcp 10.0.0.1:80: i/o timeout",
	} {
		if !containsFetchErrorPhrase([]byte(body)) {
			t.Errorf("containsFetchErrorPhrase(%q) = false, want true", body)
		}
	}
}

func TestContainsFetchErrorPhrase_Negative(t *testing.T) {
	if containsFetchErrorPhrase([]byte("results: alice, bob, admin")) {
		t.Error("containsFetchErrorPhrase should not match ordinary content")
	}
}
