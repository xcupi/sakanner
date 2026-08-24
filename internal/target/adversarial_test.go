package target

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParse_ExtremelyLongInput proves Parse rejects huge input promptly
// rather than hanging or panicking (e.g. on pathological regex/loop
// behavior), regardless of input size.
func TestParse_ExtremelyLongInput(t *testing.T) {
	sizes := []int{10_000, 100_000, 1_000_000, 10_000_000}
	for _, n := range sizes {
		n := n
		t.Run(strconv.Itoa(n)+"chars", func(t *testing.T) {
			huge := strings.Repeat("a", n) + ".com"

			done := make(chan struct{})
			var err error
			go func() {
				defer close(done)
				_, _, err = Parse(huge)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("Parse hung on a %d-byte input", n)
			}
			if err == nil {
				t.Errorf("Parse(%d-byte input) = nil error, want rejection (exceeds 253-byte hostname limit)", n)
			}
		})
	}
}

// TestParse_ManyLabels proves a hostname with an extreme number of tiny
// labels (a different pathological shape than one huge label) is also
// rejected promptly.
func TestParse_ManyLabels(t *testing.T) {
	labels := make([]string, 100_000)
	for i := range labels {
		labels[i] = "a"
	}
	huge := strings.Join(labels, ".")

	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, _, err = Parse(huge)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Parse hung on an input with 100,000 labels")
	}
	if err == nil {
		t.Error("Parse(100,000-label input) = nil error, want rejection")
	}
}

// TestParse_ControlCharactersAndNullBytes proves control characters and
// NUL bytes embedded *within* the hostname (not merely incidental
// leading/trailing whitespace, which Parse legitimately trims as normal
// input hygiene) are rejected -- this is what would matter for smuggling
// extra data past validation (e.g. a NUL-terminated-string confusion in
// some downstream consumer, or CRLF/header injection).
func TestParse_ControlCharactersAndNullBytes(t *testing.T) {
	tests := []string{
		"example.com\x00.evil.com",
		"exa\x00mple.com",
		"example.com\r\nHost: evil.com",
		string([]byte{0x01, 0x02, 0x03}) + ".com",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			value, _, err := Parse(raw)
			if err == nil {
				t.Errorf("Parse(%q) = (%q, nil), want rejection of embedded control characters", raw, value)
			}
		})
	}
}

// TestParse_TrimsIncidentalTrailingWhitespace documents the
// (intentional, non-adversarial) counterpart to the above: pure
// leading/trailing whitespace with nothing hidden after it is normal
// input hygiene, not a smuggling vector, and Parse legitimately accepts
// it after trimming.
func TestParse_TrimsIncidentalTrailingWhitespace(t *testing.T) {
	tests := []string{"example.com\n", "example.com\t", "  example.com  ", "example.com\r\n"}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			value, _, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse(%q): %v", raw, err)
			}
			if value != "example.com" {
				t.Errorf("Parse(%q) = %q, want \"example.com\"", raw, value)
			}
		})
	}
}
