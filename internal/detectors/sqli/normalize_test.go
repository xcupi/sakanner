package sqli

import "testing"

func TestNormalizeBody_CollapsesDigitRuns(t *testing.T) {
	got := normalizeBody([]byte("request-id: 12345 at 2024-01-01T00:00:42Z"))
	want := "request-id: # at #-#-#T#:#:#Z"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

func TestNormalizeBody_PreservesNonDigitContent(t *testing.T) {
	got := normalizeBody([]byte("results: alice, bob, admin"))
	want := "results: alice, bob, admin"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q (no digits to strip)", got, want)
	}
}

func TestNormalizeBody_TwoDynamicResponsesNormalizeIdentically(t *testing.T) {
	a := normalizeBody([]byte("results: (none)\n<!-- server-time: 2024-01-01T00:00:01Z request-id: 1 -->"))
	b := normalizeBody([]byte("results: (none)\n<!-- server-time: 2024-01-01T00:00:02Z request-id: 2 -->"))
	if a != b {
		t.Errorf("normalized forms differ: %q vs %q -- dynamic counters/timestamps must normalize identically", a, b)
	}
}

func TestNormalizeBody_GenuinelyDifferentContentStaysDifferent(t *testing.T) {
	a := normalizeBody([]byte("results: alice, bob, admin"))
	b := normalizeBody([]byte("results: (none)"))
	if a == b {
		t.Error("normalizeBody must not erase a genuine content difference")
	}
}

func TestNormalizeBody_EmptyBody(t *testing.T) {
	if got := normalizeBody(nil); got != "" {
		t.Errorf("normalizeBody(nil) = %q, want empty", got)
	}
}

func TestStripPayload_RemovesRawOccurrence(t *testing.T) {
	got := stripPayload([]byte("page not found: 1' OR '1'='1"), "1' OR '1'='1")
	if string(got) != "page not found: " {
		t.Errorf("stripPayload = %q, want \"page not found: \"", got)
	}
}

func TestStripPayload_RemovesHTMLEscapedOccurrence(t *testing.T) {
	got := stripPayload([]byte("You searched for: 1&#39; OR &#39;1&#39;=&#39;1"), "1' OR '1'='1")
	if string(got) != "You searched for: " {
		t.Errorf("stripPayload = %q, want \"You searched for: \"", got)
	}
}

func TestStripPayload_RemovesURLEncodedOccurrence(t *testing.T) {
	got := stripPayload([]byte("redirecting to: 1%27+OR+%271%27%3D%271"), "1' OR '1'='1")
	if string(got) != "redirecting to: " {
		t.Errorf("stripPayload = %q, want \"redirecting to: \"", got)
	}
}

func TestStripPayload_LeavesUnrelatedContentUntouched(t *testing.T) {
	got := stripPayload([]byte("results: alice, bob, admin"), "1' OR '1'='1")
	if string(got) != "results: alice, bob, admin" {
		t.Errorf("stripPayload = %q, want the input unchanged (payload never appeared)", got)
	}
}
