package evidence

import (
	"encoding/json"
	"strings"
)

// rawRequestResponseEvidence mirrors internal/detection.RequestResponseEvidence's
// JSON shape exactly (field names and tags), WITHOUT importing
// internal/detection -- this package only ever unmarshal-parses the
// JSON text every detector already produces through
// detection.NewRequestResponseEvidence, the SAME generic shape for
// every detector, never a detector-specific format. Keeping this as an
// independent struct (rather than importing internal/detection's type
// directly) keeps this package's only real dependency on the
// generically-shaped JSON contract, not a Go-level package coupling to
// the detection engine.
type rawRequestResponseEvidence struct {
	Request          string            `json:"request,omitempty"`
	Response         string            `json:"response,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	ResponseFragment string            `json:"response_fragment,omitempty"`
	Parameter        string            `json:"parameter,omitempty"`
	Payload          string            `json:"payload,omitempty"`
	Observation      string            `json:"observation,omitempty"`
	Reason           string            `json:"reason,omitempty"`
}

// parseRawEvidence best-effort unmarshals content as the generic
// RequestResponseEvidence JSON shape. ok is false when content isn't
// valid JSON in that shape at all (e.g. a plain-text EvidenceKindText
// fallback, or malformed/adversarial input) -- callers degrade
// gracefully rather than treating this as fatal; see
// buildFromPlainText in engine.go.
func parseRawEvidence(content string) (rawRequestResponseEvidence, bool) {
	var raw rawRequestResponseEvidence
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return rawRequestResponseEvidence{}, false
	}
	return raw, true
}

// parseDetectorFields extracts generic "key=value" / `key="quoted value"`
// tokens from a detector's Observation string -- task section 28's
// "detector-provided structured fields," extracted by ONE
// detector-agnostic tokenizer, never by knowledge of any specific
// detector's field names. Every detector in this project happens to
// format its Observation this way (see
// docs/phase-3-10-evidence-reproducibility.md "Detector-specific
// evidence" for the exact convention observed across all 6), but this
// parser makes no assumption about WHICH keys will appear -- an
// Observation string that doesn't follow the convention simply yields
// an empty map, never an error or a crash.
func parseDetectorFields(observation string) map[string]string {
	fields := map[string]string{}
	tokens := tokenizeKeyValue(observation)
	for _, tok := range tokens {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key := tok[:eq]
		val := strings.Trim(tok[eq+1:], `"`)
		fields[key] = val
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// tokenizeKeyValue splits s on whitespace, respecting double-quoted
// segments (so a %q-formatted value containing spaces, like SSRF's
// detail="fetched, 200 bytes", stays one token rather than being split
// apart) -- a small, generic, non-detector-specific state machine.
func tokenizeKeyValue(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case r == ' ' && !inQuotes:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// parseMethodAndPath splits a "GET /path?query HTTP/1.1"-or-"GET
// /path?query"-shaped Request line (every detector in this project
// formats it one of these two ways) into a method and the rest. Falls
// back to ("", request) if the string doesn't start with a recognized
// method token -- never panics on an unexpected shape.
func parseMethodAndPath(request string) (method, rest string) {
	fields := strings.Fields(request)
	if len(fields) == 0 {
		return "", request
	}
	first := strings.ToUpper(fields[0])
	switch first {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		if len(fields) > 1 {
			return first, fields[1]
		}
		return first, ""
	default:
		return "", request
	}
}
