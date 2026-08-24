package cmdinjectionactive

import (
	"fmt"
	"strings"
)

// labCommand is a deliberately FAKE command name -- never "echo", never
// any real shell builtin or binary -- recognized only by the lab's own
// simulated grammar (lab/harness_cmdinjection_active.go and
// lab/harness_vuln.go's own cmdInjectionPattern, which this package's
// value is byte-identical to so both Unix- and Windows-style lab
// fixtures recognize the SAME probes). Nothing in this package, or
// anywhere else in sakanner, ever invokes a real shell -- see
// docs/phase-3-26-command-injection-active.md section 1.1 and this
// package's own shell_isolation_test.go.
const labCommand = "sakanner_lab_echo"

// markerPrefix plus an exact, freshly generated per-probe token is the
// ONLY thing this detector ever treats as execution proof -- see
// docs/phase-3-26-command-injection-active.md section 2.
const markerPrefix = "COMMAND_INJECTION_MARKER:"

// commandVariant is one separator this detector tries -- the RAW,
// literal characters a target's own shell would need to see AFTER
// decoding, never a wire-encoded form (see wireEncodedPayload/
// rawPayload below for the two different encodings each location
// actually needs).
type commandVariant struct {
	name      string // short, human-readable label for evidence/logs
	separator string // raw separator characters, e.g. "|", ";", "&&", "&"
}

// commandVariants returns a small, fixed, deterministic set -- 3
// inherited verbatim from internal/detectors/cmdinjection's own
// already-reviewed set (pipe, semicolon, double-ampersand -- all valid
// POSIX-shell separators, and "|"/"&&" are ALSO valid Windows cmd.exe
// separators), plus ONE new variant (single ampersand) closing the one
// meaningful cmd.exe-specific gap a bare ";" can never reach (real
// cmd.exe does not treat ";" as a separator at all). See
// docs/phase-3-26-command-injection-active.md section 3 for why no
// OS-fingerprint-based filtering/reordering is implemented: this small
// fixed set is tried unconditionally against every target, bounded and
// deterministic regardless of target OS.
func commandVariants() []commandVariant {
	return []commandVariant{
		{name: "pipe", separator: "|"},
		{name: "semicolon", separator: ";"},
		{name: "double-ampersand", separator: "&&"},
		{name: "single-ampersand", separator: "&"},
	}
}

// wireEncodedPayload builds the query/form-string representation of
// separator+labCommand+" "+token -- for use ONLY with
// mutation.EncodingVerbatim against LocationQuery/LocationForm,
// exactly mirroring internal/detectors/cmdinjection's own existing,
// already-reviewed private technique (variants.go's own doc comment):
// "|" is sent completely RAW (Go's net/url query decoding leaves it
// alone), while every other separator character and the space before
// labCommand are percent-encoded, since Go's own url.ParseQuery
// (shared by both query-string AND application/x-www-form-urlencoded
// body parsing) treats a raw, unescaped ";" as an ALTERNATE parameter
// delimiter -- a long-standing net/url quirk -- and "&" is the
// standard delimiter, so only percent-encoding survives standard
// query/form transport for those. Confirmed directly against a real
// net/http server by the OLD detector's own already-reviewed
// development, not re-derived from scratch here.
func wireEncodedPayload(separator, token string) string {
	encodedSep := separator
	if separator != "|" {
		var b strings.Builder
		for _, r := range separator {
			fmt.Fprintf(&b, "%%%02X", r)
		}
		encodedSep = b.String()
	}
	return encodedSep + labCommand + "%20" + token
}

// rawPayload builds the LITERAL, unescaped representation of
// separator+labCommand+" "+token -- for use with LocationPath/
// LocationJSON, whose own Mutate machinery already performs exactly
// one correct escaping pass over whatever raw value is supplied
// (url.URL's own path escaper for path; json.Marshal's own string
// escaper for JSON, which needs no percent-encoding at all since none
// of these characters are JSON-special). Using wireEncodedPayload's
// PRE-encoded form for these two locations would double-encode --
// exactly the Phase 3.23 applyPath defect
// (docs/phase-3-23-path-parameters.md) this function avoids by
// construction, never by re-deriving that lesson from scratch.
func rawPayload(separator, token string) string {
	return separator + labCommand + " " + token
}
