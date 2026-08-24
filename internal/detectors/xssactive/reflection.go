package xssactive

import (
	"bytes"
	"html"
	"strings"
)

// ReflectionKind classifies exactly how (if at all) a context-revealing
// payload reflected in a response -- see
// docs/phase-3-19-active-detection.md section 8 for the full
// rationale. Deliberately NOT a full HTML/JS parser: a bounded,
// deterministic, position-based heuristic, one step more capable than
// xssreflected's own 3-bucket classifier (it additionally
// distinguishes an encoded reflection from no reflection at all,
// and a JavaScript-block context from a plain-text one).
type ReflectionKind string

const (
	// ReflectionNone means the payload (raw or encoded) was not found
	// in the response at all.
	ReflectionNone ReflectionKind = "none"
	// ReflectionHTMLEncoded means only the HTML-entity-encoded form of
	// the payload is present -- SAFE, never a finding.
	ReflectionHTMLEncoded ReflectionKind = "html_encoded"
	// ReflectionExact means the raw, unescaped payload is present in
	// ordinary HTML text (not inside a tag attribute or a <script>
	// block).
	ReflectionExact ReflectionKind = "exact"
	// ReflectionAttribute means the raw, unescaped payload is present
	// inside an HTML attribute value (an unclosed tag ending in
	// ="/=' immediately before the payload).
	ReflectionAttribute ReflectionKind = "attribute"
	// ReflectionJavaScript means the raw, unescaped payload landed
	// inside an ALREADY-OPEN <script>...</script> block in the
	// target's own page structure -- the single most directly
	// executable context this detector can identify.
	ReflectionJavaScript ReflectionKind = "javascript"
	// ReflectionJSONString means the response's own Content-Type
	// indicates JSON and the plain reflection marker was found inside
	// it -- reported at lower confidence than an HTML/JS context,
	// since whether this is exploitable depends entirely on how the
	// JSON is consumed downstream, which this detector cannot observe.
	ReflectionJSONString ReflectionKind = "json_string"
)

// classifyReflection determines where, if anywhere, payload landed in
// body. Callers only invoke this AFTER confirming (via the plain
// reflectionMarker probe) that the parameter's value reaches the
// response at all, and only for a non-JSON response -- JSON responses
// are classified directly as ReflectionJSONString from the marker
// probe (see Detect), never via this function.
func classifyReflection(body []byte, payload string) ReflectionKind {
	if bytes.Contains(body, []byte(payload)) {
		return classifyHTMLContext(body, payload)
	}
	encoded := html.EscapeString(payload)
	if encoded != payload && bytes.Contains(body, []byte(encoded)) {
		return ReflectionHTMLEncoded
	}
	return ReflectionNone
}

// classifyHTMLContext locates payload's start position and inspects
// the text immediately BEFORE it (the page's own structure prior to
// injection, never text the payload itself introduces) to determine
// which of the three "raw, unescaped" contexts applies.
func classifyHTMLContext(body []byte, payload string) ReflectionKind {
	idx := bytes.Index(body, []byte(payload))
	if idx < 0 {
		return ReflectionNone // unreachable given the caller's own bytes.Contains check, but never assume
	}
	before := string(body[:idx])

	lastOpenScript := lastIndexFold(before, "<script")
	lastCloseScript := lastIndexFold(before, "</script")
	if lastOpenScript >= 0 && lastOpenScript > lastCloseScript {
		// The ORIGINAL page already had an unclosed <script> block at
		// this position -- the payload landed inside existing,
		// already-executing script context, independent of the fresh
		// <script> tag the payload itself also happens to contain.
		return ReflectionJavaScript
	}

	lastLT := strings.LastIndex(before, "<")
	lastGT := strings.LastIndex(before, ">")
	insideTag := lastLT > lastGT
	if insideTag && (strings.HasSuffix(before, `="`) || strings.HasSuffix(before, `='`)) {
		return ReflectionAttribute
	}
	return ReflectionExact
}

func lastIndexFold(s, substr string) int {
	return strings.LastIndex(strings.ToLower(s), strings.ToLower(substr))
}

// isJSONContentType reports whether ct (an HTTP Content-Type header
// value) indicates a JSON body -- the same substring-match idiom
// internal/crawler/internal/parameters already use to detect HTML/
// JSON, applied here.
func isJSONContentType(ct string) bool {
	return ct != "" && strings.Contains(strings.ToLower(ct), "json")
}
