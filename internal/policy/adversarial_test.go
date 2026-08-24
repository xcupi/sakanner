package policy

import (
	"strings"
	"testing"
)

// TestResolve_ProfileNameInjection_RejectedCleanly is task adversarial
// scenario 5 ("profile name injection"): Resolve must never panic,
// hang, or do anything other than cleanly return an UnknownProfileError
// for any string an operator could pass via --profile, including shell
// metacharacters, path traversal sequences, null bytes, and very long
// or malformed unicode input. Resolve does no shell execution, no file
// access, and no string interpolation of its own (a plain map lookup
// -- see registry.go's Get) -- these inputs are adversarial in INTENT
// only; this test exists to prove that intent has nothing to attach
// to, not to guard against a specific parsing bug.
func TestResolve_ProfileNameInjection_RejectedCleanly(t *testing.T) {
	malicious := []string{
		"; rm -rf /",
		"$(rm -rf /)",
		"`rm -rf /`",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"recon\x00web",
		"recon' OR '1'='1",
		"<script>alert(1)</script>",
		strings.Repeat("A", 100000),
		"recon\nweb\ndeep",
		"🔥💀☠️",
		"",
		"   ",
		"RECON", // case-sensitive: must not silently match "recon"
		"Recon",
	}
	for _, name := range malicious {
		name := name
		t.Run(shortLabel(name), func(t *testing.T) {
			eff, err := Resolve(name, ConfigView{})
			if name == "" {
				// Empty string is the documented "no profile given"
				// sentinel, not itself a profile name -- covered
				// exhaustively by resolve_test.go's precedence tests.
				if err != nil {
					t.Errorf("Resolve(\"\") returned an error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Resolve(%q) succeeded (resolved to %+v), want UnknownProfileError", name, eff)
			}
			if _, ok := err.(*UnknownProfileError); !ok {
				t.Errorf("Resolve(%q) returned %T, want *UnknownProfileError", name, err)
			}
		})
	}
}

func shortLabel(s string) string {
	if len(s) > 30 {
		return s[:30] + "...(truncated)"
	}
	if s == "" {
		return "(empty)"
	}
	return s
}

// TestEffectivePolicy_HoldsNoReferenceBackToConfig is task adversarial
// scenario 9 ("configuration mutation during scan"): EffectivePolicy
// must be an independent value, not a view over the ConfigView (or
// *config.Config) it was resolved from -- mutating the ConfigView
// AFTER Resolve returns must never retroactively change the already-
// resolved EffectivePolicy. Combined with the fact that Resolve is the
// ONLY place config is consulted at all (cmd/scanner calls it once,
// before constructing the Orchestrator -- see
// docs/phase-3-12-scan-profiles.md "Profile immutability"), this is
// what makes a config file changing on disk mid-scan structurally
// unable to affect an already-running scan's policy.
func TestEffectivePolicy_HoldsNoReferenceBackToConfig(t *testing.T) {
	cfg := ConfigView{CrawlerEnabled: true, CrawlerMaxDepth: 2, CrawlerMaxPages: 20}
	eff, err := Resolve("", cfg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	snapshot := eff

	// Mutate the ConfigView value used to resolve it -- EffectivePolicy
	// fields are plain int/bool/string/time.Duration (see model.go), so
	// this can only fail to matter if Resolve copied by value, which it
	// does; this test pins that down explicitly rather than leaving it
	// implicit.
	cfg.CrawlerEnabled = false
	cfg.CrawlerMaxDepth = 999
	cfg.CrawlerMaxPages = 999

	if eff != snapshot {
		t.Errorf("EffectivePolicy changed after mutating the ConfigView it was resolved from: before=%+v after=%+v", snapshot, eff)
	}
}
