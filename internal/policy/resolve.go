package policy

import (
	"fmt"
	"strings"
)

// UnknownProfileError is returned when --profile names a profile this
// build does not have. Its Error() matches the task's exact required
// wording: `unknown scan profile "something"` followed by an
// "Available profiles:" list -- cmd/scanner prints this and exits
// non-zero WITHOUT constructing an Orchestrator, a Pipeline, or making
// any network call (task's "no network activity, no scan job created
// if possible").
type UnknownProfileError struct {
	Name      string
	Available []string
}

func (e *UnknownProfileError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown scan profile %q\nAvailable profiles:", e.Name)
	for _, name := range e.Available {
		fmt.Fprintf(&b, "\n  %s", name)
	}
	return b.String()
}

// ConfigView is the subset of *internal/config.Config the no-profile
// fallback path below needs. Defined here (rather than importing
// internal/config directly) so this package has no dependency on
// config's own struct shape beyond the 3 fields that actually matter
// to profile resolution -- cmd/scanner passes its already-loaded
// *config.Config in as a ConfigView literal. Every other config field
// (DNS timeouts, port lists, tool backends, detection worker/rate
// settings, ...) is untouched by profiles and keeps flowing from
// *config.Config directly, exactly as before this phase.
type ConfigView struct {
	CrawlerEnabled  bool
	CrawlerMaxDepth int
	CrawlerMaxPages int
}

// Resolve implements task's "CLI input -> Profile resolver -> Effective
// scan policy" stage and its exact required precedence: "CLI profile >
// explicit configuration > default profile."
//
//  1. profileFlag non-empty (an operator passed --profile explicitly):
//     that profile's own settings are used UNCONDITIONALLY -- cfg is
//     never consulted for crawler/detection fields once a profile is
//     named, so `--profile recon` with crawler.enabled: true in the
//     config file still produces a fully crawler-disabled policy. This
//     is what makes the combination deterministic rather than
//     ambiguous (task: "reject contradictory overrides, or define
//     explicit precedence, but never silently produce surprising
//     behavior") -- the profile always wins, full stop, no partial
//     merge of the two.
//  2. profileFlag empty AND cfg.CrawlerEnabled true (the operator has
//     genuine, explicit config-file crawler settings -- the ONLY way
//     to reach true, since sakanner's own config default is false):
//     "explicit configuration" wins over the default profile, exactly
//     reproducing this codebase's pre-3.12 behavior (crawler on with
//     the config's own depth/pages, detection attempted) so an
//     existing config-driven setup is not silently downgraded by
//     profiles merely existing.
//  3. Otherwise: the "recon" default profile applies.
//
// Resolve is pure: no I/O, no clock/random/env/CPU-count reads, no
// network access -- calling it twice with the same arguments always
// returns byte-identical results (task's determinism requirement).
// Scope is never consulted or affected here at all; see this package's
// doc comment for why that is a completely separate, unmodified
// mechanism.
func Resolve(profileFlag string, cfg ConfigView) (EffectivePolicy, error) {
	reg := DefaultRegistry()

	if profileFlag != "" {
		p, ok := reg.Get(profileFlag)
		if !ok {
			return EffectivePolicy{}, &UnknownProfileError{Name: profileFlag, Available: reg.Names()}
		}
		return p.effectivePolicy(), nil
	}

	if cfg.CrawlerEnabled {
		return legacyConfigPolicy(cfg), nil
	}

	p, ok := reg.Get(DefaultProfileName)
	if !ok {
		// Unreachable: DefaultProfileName names one of builtinProfiles
		// above. Guarded rather than assumed so a future edit that
		// renames/removes the default profile fails loudly here instead
		// of silently resolving to a zero-value EffectivePolicy.
		return EffectivePolicy{}, fmt.Errorf("policy: default profile %q is not registered", DefaultProfileName)
	}
	return p.effectivePolicy(), nil
}

// legacyConfigPolicy reproduces this codebase's pre-3.12 no-profile
// behavior exactly: crawler on with the config file's own depth/pages,
// detection enabled (attempted, subject to the pre-existing State A/B/C
// eligible-targets logic, entirely unchanged by this phase) -- task's
// "explicit configuration" precedence tier. Resource limits use "web"'s
// own values (task does not ask for a distinct resource class here;
// this is the closest existing profile's shape, applied rather than
// inventing a fourth, undocumented resource tier).
func legacyConfigPolicy(cfg ConfigView) EffectivePolicy {
	web, _ := DefaultRegistry().Get("web")
	ep := web.effectivePolicy()
	ep.ProfileName = "web (config-driven, no --profile given)"
	ep.CrawlMaxDepth = cfg.CrawlerMaxDepth
	ep.CrawlMaxPages = cfg.CrawlerMaxPages
	return ep
}
