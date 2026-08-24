package main

import (
	"encoding/json"
	"strings"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// buildCurlReproduction constructs a sanitized, informational,
// curl-like reproduction of f's own most specific stored evidence --
// see docs/phase-3-32-operator-workflow.md section 4 for the full
// design and its own documented limitations. This function NEVER
// executes anything (no os/exec, no net/http) -- it only ever returns
// a string for the caller to print. notes explains anything the
// reproduction could not represent (e.g. no evidence available).
func buildCurlReproduction(f models.Finding) (cmd string, notes []string) {
	item, ok := mostSpecificRequestResponseEvidence(f)
	if !ok {
		return "", []string{"no request/response evidence available to build a reproduction from"}
	}

	method, url, ok := splitRequestLine(item.Request)
	if !ok || method == "" || url == "" {
		return "", []string{"stored evidence's own request line could not be parsed"}
	}

	parts := []string{"curl", "-X", shellQuote(method), shellQuote(url)}
	if item.Parameter != "" && item.Payload != "" && !strings.EqualFold(method, "GET") {
		parts = append(parts, "-d", shellQuote(item.Parameter+"="+item.Payload))
		notes = append(notes, "reconstructed from the finding's own stored evidence only -- if the original request had other form/JSON fields, only the single TESTED parameter is reproduced here")
	}
	if item.Parameter != "" && item.Payload != "" && strings.EqualFold(method, "GET") {
		notes = append(notes, "the tested parameter is already embedded in the URL's own query string above")
	}
	notes = append(notes, "this command is INFORMATION ONLY -- sakanner never executes it; run it yourself only if you understand and are authorized to do so")
	return strings.Join(parts, " "), notes
}

// mostSpecificRequestResponseEvidence returns the LAST
// EvidenceKindRequestResponse item on f that parses as a
// detection.RequestResponseEvidence with a non-empty Request line --
// mirroring every detector's own established evidence ordering
// (baseline first, confirmed/proof evidence last), so this always
// prefers the actual CONFIRMING probe over the baseline.
func mostSpecificRequestResponseEvidence(f models.Finding) (detection.RequestResponseEvidence, bool) {
	for i := len(f.Evidence) - 1; i >= 0; i-- {
		e := f.Evidence[i]
		if e.Kind != models.EvidenceKindRequestResponse && e.Kind != models.EvidenceKindBaseline {
			continue
		}
		var item detection.RequestResponseEvidence
		if err := json.Unmarshal([]byte(e.Content), &item); err != nil {
			continue
		}
		if item.Request != "" {
			return item, true
		}
	}
	return detection.RequestResponseEvidence{}, false
}

// splitRequestLine parses "METHOD URL" (detection.MutationEvidence's
// own established Request field format, e.g. "GET http://host/path")
// into its two parts.
func splitRequestLine(line string) (method, url string, ok bool) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// shellQuote wraps s in single quotes, escaping any embedded single
// quote as '\” (the standard POSIX-shell-safe technique: close the
// quote, emit an escaped literal quote, reopen the quote) -- so a
// malicious value (however it reached stored evidence) can never
// break out of its own quoted argument if an operator chooses to
// paste and run the generated command. Used for EVERY value placed
// into a generated reproduction command, never selectively.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
