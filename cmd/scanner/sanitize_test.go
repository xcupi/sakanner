package main

import (
	"strings"
	"testing"
)

func TestSanitizeForTerminal_StripsANSIEscape(t *testing.T) {
	// ESC (0x1B) is the lead byte of every ANSI/terminal escape
	// sequence -- e.g. "\x1b[2J" clears the screen, "\x1b]0;title\x07"
	// can rewrite the terminal's own title bar.
	in := "before\x1b[31mRED\x1b[0mafter"
	out := sanitizeForTerminal(in)
	if strings.ContainsRune(out, 0x1B) {
		t.Errorf("SECURITY: ESC byte survived sanitization: %q", out)
	}
	if !strings.Contains(out, "before") || !strings.Contains(out, "RED") || !strings.Contains(out, "after") {
		t.Errorf("sanitized output lost legitimate text: %q", out)
	}
}

func TestSanitizeForTerminal_StripsCarriageReturn(t *testing.T) {
	// A bare \r can overwrite the current terminal line -- a
	// target-controlled title/description containing "\rSTATUS: SAFE"
	// could visually hide the real, preceding text.
	in := "REAL WARNING\rSTATUS: SAFE"
	out := sanitizeForTerminal(in)
	if strings.ContainsRune(out, '\r') {
		t.Errorf("SECURITY: carriage return survived sanitization: %q", out)
	}
}

func TestSanitizeForTerminal_StripsOtherControlChars(t *testing.T) {
	in := "a\x00b\x01c\x07d\x7Fe"
	out := sanitizeForTerminal(in)
	for _, r := range out {
		if r < 0x20 && r != '\n' && r != '\t' {
			t.Errorf("SECURITY: control character U+%04X survived sanitization: %q", r, out)
		}
		if r == 0x7F {
			t.Errorf("SECURITY: DEL character survived sanitization: %q", out)
		}
	}
}

func TestSanitizeForTerminal_PreservesNewlinesAndTabs(t *testing.T) {
	in := "line1\nline2\tindented"
	out := sanitizeForTerminal(in)
	if out != in {
		t.Errorf("sanitizeForTerminal(%q) = %q, want unchanged (newlines/tabs are legitimate)", in, out)
	}
}

func TestSanitizeForTerminal_PreservesOrdinaryText(t *testing.T) {
	in := "GET /search?q=hello world! 100% safe -- (test) [ok]"
	out := sanitizeForTerminal(in)
	if out != in {
		t.Errorf("sanitizeForTerminal(%q) = %q, want unchanged", in, out)
	}
}

func TestSanitizeForTerminal_EmptyString(t *testing.T) {
	if sanitizeForTerminal("") != "" {
		t.Error("expected empty string to remain empty")
	}
}

func TestSanitizeSlice_AppliesToEveryElement(t *testing.T) {
	in := []string{"safe", "with\x1bescape", "with\rCR"}
	out := sanitizeSlice(in)
	for i, v := range out {
		for _, r := range v {
			if r == 0x1B || r == '\r' {
				t.Errorf("element %d (%q) still contains a control/escape character", i, v)
			}
		}
	}
}
