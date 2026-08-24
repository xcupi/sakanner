package main

import "strings"

// sanitizeForTerminal strips ASCII control characters (0x00-0x1F,
// excluding tab, and 0x7F) and the ESC byte (0x1B, the lead byte of
// every ANSI/terminal escape sequence) from s -- applied to every
// finding/chain-derived string this package's own commands print.
// Every such string ultimately originates from a DETECTOR'S OWN
// interaction with a target the operator does not fully control
// (title/description/evidence/URL text); without this, a target
// response containing a raw terminal-control or ANSI escape sequence
// would be echoed verbatim to the operator's own terminal, able to
// manipulate what they see (overwrite previously-printed lines, spoof
// a prompt, hide subsequent output). Newlines are preserved
// (multi-line evidence content is expected and legitimate) but a
// bare carriage return (which alone can overwrite the current
// terminal line) is stripped.
// sanitizeSlice applies sanitizeForTerminal to every element of ss --
// used before printing a []string field (e.g. via %v) so no single
// element can smuggle a control/escape sequence into the printed
// slice representation.
func sanitizeSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, v := range ss {
		out[i] = sanitizeForTerminal(v)
	}
	return out
}

func sanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == 0x7F: // DEL
			continue
		case r < 0x20: // includes \r (0x0D) and ESC (0x1B)
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
