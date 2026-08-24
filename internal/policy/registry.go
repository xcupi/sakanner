package policy

import (
	"sort"
	"time"
)

// DefaultProfileName is the profile used whenever an operator does not
// supply --profile AND has no config-driven crawler settings of their
// own (see resolve.go) -- task's explicit "DEFAULT PROFILE: recon."
// The scanner already defaults to crawler disabled; choosing "recon"
// here means adding profiles never makes a plain `scanner scan
// <target>` invocation MORE active than it already was.
const DefaultProfileName = "recon"

// builtinProfiles is the fixed, deterministic set of profiles this
// build ships -- task's "3 initial profiles." Never mutated at
// runtime: Registry.List/Get always read from this same literal slice,
// so resolution never depends on registration order, time, or any
// external state (task's determinism requirement).
//
// Numbers chosen for each profile (documented per-field below) are
// deliberately bounded even for "deep" -- task's explicit "deep is not
// an excuse for unlimited scanning."
var builtinProfiles = []Profile{
	{
		Name:        "recon",
		Description: "Reconnaissance only: hosts, ports, HTTP services, technologies. No crawling, no vulnerability detection.",
		// Crawling off entirely -- nothing to bound, but MaxDepth/
		// MaxPages still hold defined, non-misleading values (never 0
		// read as "unlimited").
		CrawlEnabled:  false,
		CrawlMaxDepth: 0,
		CrawlMaxPages: 0,
		// Detection structurally disabled (task's "detection =
		// disabled, distinctly" requirement) -- Orchestrator.Run never
		// even invokes the detection engine for this profile; see
		// resolve.go and internal/orchestrator's DetectionDisabled
		// option.
		DetectionEnabled:     false,
		VerificationEnabled:  false,
		EvidenceEnabled:      false,
		ResourceClass:        ResourceClassLow,
		DetectionConcurrency: 1,
		ScanTimeout:          5 * time.Minute,
		StageTimeout:         2 * time.Minute,
		// Input discovery (Phase 3.13) never runs under this profile
		// (CrawlEnabled=false) -- these bounds are never consulted, kept
		// at 0 rather than a positive placeholder for the same reason
		// CrawlMaxDepth/CrawlMaxPages are 0 above.
		MaxInputsPerEndpoint: 0,
		MaxTotalInputs:       0,
	},
	{
		Name:         "web",
		Description:  "Recon plus bounded crawling and vulnerability detection against discovered, parameterized endpoints.",
		CrawlEnabled: true,
		// Matches this codebase's own pre-existing crawler.max_depth/
		// crawler.max_pages defaults (internal/config.setDefaults) --
		// "web" does not invent new numbers where the established,
		// already-reviewed defaults already describe a sensible bounded
		// crawl.
		CrawlMaxDepth:        2,
		CrawlMaxPages:        20,
		DetectionEnabled:     true,
		VerificationEnabled:  true,
		EvidenceEnabled:      true,
		ResourceClass:        ResourceClassMedium,
		DetectionConcurrency: 5,
		ScanTimeout:          10 * time.Minute,
		StageTimeout:         5 * time.Minute,
		// Matches internal/parameters.DefaultLimits() exactly -- "web"
		// does not invent new bounds where an already-reviewed default
		// already describes a sensible bound, same rationale as its
		// crawl depth/pages above.
		MaxInputsPerEndpoint: 100,
		MaxTotalInputs:       2000,
	},
	{
		Name:         "deep",
		Description:  "Recon plus deeper, still-bounded crawling and vulnerability detection. Not exploitation -- same detectors as \"web\", larger discovery and concurrency bounds.",
		CrawlEnabled: true,
		// Deeper than "web" but explicitly finite: 4 link-hops and 75
		// pages, not "as many as exist." Chosen to meaningfully widen
		// discovery on a real target without approaching "crawl the
		// entire site" territory.
		CrawlMaxDepth:        4,
		CrawlMaxPages:        75,
		DetectionEnabled:     true,
		VerificationEnabled:  true,
		EvidenceEnabled:      true,
		ResourceClass:        ResourceClassHigh,
		DetectionConcurrency: 10,
		ScanTimeout:          20 * time.Minute,
		StageTimeout:         10 * time.Minute,
		// Deeper than "web" but still explicitly finite -- same
		// reasoning as CrawlMaxDepth/CrawlMaxPages above.
		MaxInputsPerEndpoint: 200,
		MaxTotalInputs:       5000,
	},
}

// Registry is a read-only view over the built-in profile set. There is
// no way to register, mutate, or remove a profile at runtime --
// task's own scope explicitly does not ask for that, and a fixed set
// is what keeps resolution deterministic (task's determinism
// requirement: "not dependent on ... filesystem ordering" or any other
// runtime state).
type Registry struct {
	byName map[string]Profile
	order  []string
}

// DefaultRegistry returns the Registry over this build's fixed profile
// set. Cheap to call repeatedly (no I/O, builds a small map from the
// package-level literal above) -- callers are not expected to cache it,
// though nothing prevents that either.
func DefaultRegistry() *Registry {
	r := &Registry{byName: make(map[string]Profile, len(builtinProfiles))}
	for _, p := range builtinProfiles {
		r.byName[p.Name] = p
		r.order = append(r.order, p.Name)
	}
	return r
}

// Get looks up one profile by exact, case-sensitive name.
func (r *Registry) Get(name string) (Profile, bool) {
	p, ok := r.byName[name]
	return p, ok
}

// List returns every profile in a fixed, deterministic order (built-in
// declaration order, not map iteration order) -- task's "PROFILE
// REGISTRY" test requirement and `scanner profiles list`'s own
// row order.
func (r *Registry) List() []Profile {
	out := make([]Profile, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.byName[name])
	}
	return out
}

// Names returns every registered profile name, sorted -- used to build
// the "Available profiles:" list in an unknown-profile error (task's
// exact required error format) and in shell completion.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
