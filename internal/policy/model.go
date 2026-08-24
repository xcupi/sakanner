// Package policy implements sakanner's Phase 3.12 scan profile and
// detection policy engine: a small, centralized layer that turns an
// operator's profile choice ("recon", "web", "deep", or none at all)
// into a single, immutable EffectivePolicy -- concrete crawler/
// detection/resource values -- BEFORE any scan starts.
//
// This is the ONLY package in the codebase that knows profile NAMES or
// contains any "if profile == X" branching. Every other package
// (internal/orchestrator, internal/orchestration, cmd/scanner) consumes
// an already-resolved EffectivePolicy's plain fields, never a profile
// identity -- see docs/phase-3-12-scan-profiles.md "Architecture: why
// profile logic lives in one place."
//
// Profiles never touch scope. Resolving a policy is pure, in-memory,
// deterministic computation over a profile name and a *config.Config --
// no network access, no scope-rule mutation, no filesystem access
// beyond the config the caller already loaded. Scope validation
// happens exactly where it always has (internal/orchestrator's own
// SCOPE stage, internal/scope.Validator), entirely independent of
// which profile is active -- see resolve.go's doc comment.
package policy

import "time"

// ResourceClass is a coarse, human-readable label for how much load a
// profile's resource limits represent -- shown in `scanner profiles
// list`/`show` (task's CLI table "RESOURCE CLASS" column), never
// itself a control value anything branches on.
type ResourceClass string

const (
	ResourceClassLow    ResourceClass = "low"
	ResourceClassMedium ResourceClass = "medium"
	ResourceClassHigh   ResourceClass = "high"
)

// Profile is one named, declarative scan profile -- task's "first-class
// Profile model" (Recon/Crawler/Detection/Verification/Evidence
// configuration, resource limits). Deliberately NOT a copy of
// internal/config.Config: a profile only carries the handful of fields
// this phase's 3 profiles actually need to differ on, not sakanner's
// entire configuration surface (DNS timeouts, port lists, tool
// backends, etc. stay exactly where they already lived, in
// *config.Config, since no profile changes them).
type Profile struct {
	Name        string
	Description string

	// Crawler configuration (task's "Crawler configuration" field).
	// CrawlEnabled false makes MaxDepth/MaxPages irrelevant, but they
	// still hold defined, bounded values (never left at Go's zero
	// value) so nothing downstream can misread "0" as "unlimited."
	CrawlEnabled  bool
	CrawlMaxDepth int
	CrawlMaxPages int

	// Detection configuration (task's "Detection configuration" +
	// "Verification configuration" fields). VerificationEnabled always
	// mirrors DetectionEnabled in this build: every real detector
	// performs its own verification inside one Detect() call (see
	// docs/phase-3-11-scan-orchestrator.md "Why VERIFICATION has no
	// separate checkpoint") -- there is no independent verification
	// toggle to control yet. Modeled as its own field anyway, honestly
	// documented as derived rather than independently controllable, so
	// the Profile type doesn't have to change shape if that ever stops
	// being true.
	DetectionEnabled    bool
	VerificationEnabled bool

	// EvidenceEnabled mirrors DetectionEnabled for the same reason:
	// Phase 3.10 evidence collection only ever has something to collect
	// evidence FOR when detection ran (task's "Evidence configuration"
	// field, modeled honestly rather than as an independent knob).
	EvidenceEnabled bool

	// Resource limits (task's "Resource limits" field) -- task section
	// "no unlimited values": every profile, including "deep," defines
	// concrete, bounded values here. See registry.go's doc comments on
	// each built-in profile for the reasoning behind its specific
	// numbers.
	ResourceClass        ResourceClass
	DetectionConcurrency int
	ScanTimeout          time.Duration
	StageTimeout         time.Duration

	// MaxInputsPerEndpoint/MaxTotalInputs bound Phase 3.13 input
	// discovery (internal/parameters.Limits) -- gated by the SAME
	// CrawlEnabled above, never an independent toggle (Phase 3.13
	// task's "PROFILE INTERACTION": recon stays passive/off, web is
	// bounded, deep is bounded higher). 0 for "recon" is not "unlimited"
	// -- it is simply never consulted, since CrawlEnabled=false means
	// input discovery never runs at all for that profile.
	MaxInputsPerEndpoint int
	MaxTotalInputs       int
}

// EffectivePolicy is the fully resolved, immutable result of Resolve --
// task's "effective immutable scan policy." Its fields are exactly
// what internal/orchestrator and cmd/scanner need to configure one
// scan: crawler enabled/depth/pages, detection execution enabled/
// disabled, verification enabled/disabled, evidence collection mode,
// concurrency/resource class, and resource limits (task's explicit
// field list) -- and nothing else. It does not expose HOW it was
// derived (which profile, or the config-fallback path resolve.go took
// to get here) beyond the ProfileName label carried through to
// Result.Profile for the operator's own reference.
//
// An EffectivePolicy is a plain value (no pointers to mutable state,
// no methods that mutate it): once Resolve returns one, nothing --
// including a config file changing on disk mid-scan -- can alter it.
// See resolve.go's doc comment for why this makes profile immutability
// (task's requirement) automatic rather than something Orchestrator.Run
// has to separately enforce.
type EffectivePolicy struct {
	// ProfileName is the resolved profile's own Name, OR
	// "web (config-driven, no --profile given)" -- see resolve.go's
	// legacyConfigPolicy -- OR "recon (default)" when neither an
	// explicit --profile nor config-driven crawler settings applied.
	// Carried into Result.Profile (task's "Profile: field") purely for
	// operator visibility; nothing branches on its value downstream.
	ProfileName string

	CrawlEnabled  bool
	CrawlMaxDepth int
	CrawlMaxPages int

	DetectionEnabled    bool
	VerificationEnabled bool
	EvidenceEnabled     bool

	ResourceClass        ResourceClass
	DetectionConcurrency int
	ScanTimeout          time.Duration
	StageTimeout         time.Duration

	MaxInputsPerEndpoint int
	MaxTotalInputs       int
}

// effectivePolicy turns a Profile into an EffectivePolicy -- a pure,
// deterministic copy with no config dependency, since every field a
// Profile defines is already a concrete, self-contained value (task's
// determinism requirement: a profile's own resolution never depends on
// the config file's crawler/detection sections at all -- only
// resolve.go's no-profile-given fallback path reads those).
func (p Profile) effectivePolicy() EffectivePolicy {
	return EffectivePolicy{
		ProfileName:          p.Name,
		CrawlEnabled:         p.CrawlEnabled,
		CrawlMaxDepth:        p.CrawlMaxDepth,
		CrawlMaxPages:        p.CrawlMaxPages,
		DetectionEnabled:     p.DetectionEnabled,
		VerificationEnabled:  p.VerificationEnabled,
		EvidenceEnabled:      p.EvidenceEnabled,
		ResourceClass:        p.ResourceClass,
		DetectionConcurrency: p.DetectionConcurrency,
		ScanTimeout:          p.ScanTimeout,
		StageTimeout:         p.StageTimeout,
		MaxInputsPerEndpoint: p.MaxInputsPerEndpoint,
		MaxTotalInputs:       p.MaxTotalInputs,
	}
}
