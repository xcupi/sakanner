package openredirectactive

import (
	"net/url"
	"strings"
)

// redirectVariant pairs one wire representation of the configured
// destination with the mutation.Encoding it must be sent with -- see
// docs/phase-3-28-open-redirect-active.md section 4 for why each
// variant needs its own encoding.
type redirectVariant struct {
	name  string
	value string
	// verbatim is true for a payload this package has already
	// percent-encoded itself -- it must be sent via
	// mutation.EncodingVerbatim to avoid the query/form encoder
	// double-encoding it, mirroring every prior "-active" detector's
	// own identical "encoded variant" precedent.
	verbatim bool
}

// wireVariants returns the small, fixed set of representations tried
// against query/form locations: the destination verbatim (absolute),
// protocol-relative (scheme stripped), and manually percent-encoded
// (sent verbatim to avoid double-encoding).
func wireVariants(destination string) []redirectVariant {
	return []redirectVariant{
		{name: "absolute", value: destination},
		{name: "protocol-relative", value: protocolRelative(destination)},
		{name: "percent-encoded", value: percentEncodeAll(destination), verbatim: true},
	}
}

// rawPayload is the single representation tried against path/JSON
// locations -- their own downstream escaping (url.URL.String()'s path
// escaper / json.Marshal) handles it correctly without manual
// pre-encoding, mirroring traversalactive/cmdinjectionactive's
// identical path/JSON treatment.
func rawPayload(destination string) string { return destination }

// protocolRelative strips destination's "scheme:" prefix, leaving a
// protocol-relative reference ("//host/path") -- a real, common open-
// redirect filter bypass (naive filters checking for an "http"
// prefix miss this form entirely; browsers and net/http's own
// url.ResolveReference both treat it as a full authority change).
func protocolRelative(destination string) string {
	if idx := strings.Index(destination, "://"); idx >= 0 {
		return destination[idx+1:]
	}
	return destination
}

// percentEncodeAll manually percent-encodes every byte of destination
// that isn't in a small unreserved safe set, producing a payload this
// package sends via mutation.EncodingVerbatim so the query/form
// encoder's own escaping pass never touches it (which would otherwise
// double-encode "%3A" into "%253A"). A normal HTTP server decodes this
// exactly once when reading the query/form value, arriving at the
// same destination string as the "absolute" variant -- this variant
// exists to prove detection survives an already-wire-encoded
// representation, not to reach a differently-behaving code path in
// the fixture.
func percentEncodeAll(destination string) string {
	var b strings.Builder
	for i := 0; i < len(destination); i++ {
		c := destination[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteString(url.QueryEscape(string(c)))
		}
	}
	return b.String()
}
