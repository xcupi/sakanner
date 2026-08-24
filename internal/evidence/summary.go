package evidence

import (
	"fmt"
	"strings"

	"sakanner/internal/correlation"
)

// vulnerabilityTypeLabel maps this project's snake_case
// vulnerability_type values to a human-readable label -- a fixed,
// deterministic lookup table, not free-text generation. An
// unrecognized type falls back to a straightforward transformation
// (underscores to spaces) rather than a hardcoded "unknown" string, so
// a future detector's type still produces a readable (if less
// polished) summary without this package needing an update first.
var vulnerabilityTypeLabel = map[string]string{
	"reflected_xss":     "Reflected XSS",
	"sql_injection":     "SQL Injection",
	"ssrf":              "SSRF",
	"idor":              "IDOR/BOLA",
	"path_traversal":    "Path Traversal",
	"command_injection": "Command Injection",
}

func labelFor(vulnType string) string {
	if l, ok := vulnerabilityTypeLabel[vulnType]; ok {
		return l
	}
	return strings.ReplaceAll(vulnType, "_", " ")
}

// Summarize builds task section 30's deterministic, human-readable
// summary entirely from structured fields already on cf and verification
// -- no LLM, no free-form generation. Matches the task's own example
// shape: "{Type} was confirmed in parameter '{param}' on {path}. {detail}."
func Summarize(cf correlation.CanonicalFinding, verification string) string {
	label := labelFor(cf.VulnerabilityType)
	param := cf.HTTP.Parameter
	path := cf.Asset.Path

	var sb strings.Builder
	if param != "" {
		fmt.Fprintf(&sb, "%s was confirmed in parameter %q on %s.", label, param, path)
	} else {
		fmt.Fprintf(&sb, "%s was confirmed on %s.", label, path)
	}
	if verification != "" {
		sb.WriteString(" ")
		sb.WriteString(verification)
	}
	return sb.String()
}

// WhyVulnerable builds task section 31's deterministic reasoning --
// again entirely from structured fields, never a claim unsupported by
// the evidence: it states what was supplied, where, and what the
// detector's own Reason text (already deterministic, already
// detector-produced) says confirms the vulnerability, never inventing
// new justification of its own.
func WhyVulnerable(cf correlation.CanonicalFinding, reason string) string {
	param := cf.HTTP.Parameter
	path := cf.Asset.Path

	var sb strings.Builder
	if param != "" {
		fmt.Fprintf(&sb, "Input supplied to parameter %q on %s was not handled safely.", param, path)
	} else {
		fmt.Fprintf(&sb, "Input supplied to %s was not handled safely.", path)
	}
	if reason != "" {
		sb.WriteString(" ")
		sb.WriteString(reason)
	}
	return sb.String()
}
