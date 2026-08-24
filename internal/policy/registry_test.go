package policy

import (
	"testing"
)

func TestRegistry_HasExactlyThreeBuiltinProfiles(t *testing.T) {
	names := DefaultRegistry().Names()
	if len(names) != 3 {
		t.Fatalf("got %d profiles, want 3: %v", len(names), names)
	}
	for _, want := range []string{"recon", "web", "deep"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing profile %q", want)
		}
	}
}

func TestRegistry_ListOrderIsDeterministicAcrossCalls(t *testing.T) {
	first := DefaultRegistry().List()
	for i := 0; i < 20; i++ {
		got := DefaultRegistry().List()
		if len(got) != len(first) {
			t.Fatalf("call %d: length changed: got %d want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Name != first[j].Name {
				t.Fatalf("call %d: order changed at index %d: got %q want %q", i, j, got[j].Name, first[j].Name)
			}
		}
	}
}

func TestRegistry_NamesAreSorted(t *testing.T) {
	names := DefaultRegistry().Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names() not sorted: %v", names)
		}
	}
}

// TestRegistry_NoDuplicateProfileNames is task adversarial scenario 11
// ("duplicate profile registration"): there is no runtime registration
// API at all (profiles are a fixed compiled-in slice, Registry has no
// Register method), so this can only happen via a future edit to
// builtinProfiles itself -- guarded here so such an edit fails a test
// immediately rather than silently losing a profile to map-key
// collision in DefaultRegistry.
func TestRegistry_NoDuplicateProfileNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range builtinProfiles {
		if seen[p.Name] {
			t.Errorf("duplicate profile name %q in builtinProfiles", p.Name)
		}
		seen[p.Name] = true
	}
}

// TestRegistry_DeepProfile_InputLimits_HigherThanWeb_ButBounded is
// Phase 3.13's own extension of the deep-vs-web resource-limit
// pattern, applied to input discovery.
func TestRegistry_DeepProfile_InputLimits_HigherThanWeb_ButBounded(t *testing.T) {
	web, _ := DefaultRegistry().Get("web")
	deep, _ := DefaultRegistry().Get("deep")

	if deep.MaxInputsPerEndpoint <= web.MaxInputsPerEndpoint {
		t.Errorf("deep.MaxInputsPerEndpoint (%d) must exceed web's (%d)", deep.MaxInputsPerEndpoint, web.MaxInputsPerEndpoint)
	}
	if deep.MaxTotalInputs <= web.MaxTotalInputs {
		t.Errorf("deep.MaxTotalInputs (%d) must exceed web's (%d)", deep.MaxTotalInputs, web.MaxTotalInputs)
	}
	for _, p := range []Profile{web, deep} {
		if p.MaxInputsPerEndpoint <= 0 {
			t.Errorf("%s: MaxInputsPerEndpoint must be positive (bounded), got %d", p.Name, p.MaxInputsPerEndpoint)
		}
		if p.MaxTotalInputs <= 0 {
			t.Errorf("%s: MaxTotalInputs must be positive (bounded), got %d", p.Name, p.MaxTotalInputs)
		}
	}
}

func TestRegistry_ReconProfile_InputLimitsIrrelevantButDefined(t *testing.T) {
	recon, _ := DefaultRegistry().Get("recon")
	if recon.CrawlEnabled {
		t.Fatal("test assumption violated: recon must have CrawlEnabled=false")
	}
	// 0 here is correct (never "unlimited"): CrawlEnabled=false means
	// input discovery never runs at all for this profile, so these
	// bounds are never consulted -- see registry.go's own comment.
	if recon.MaxInputsPerEndpoint != 0 || recon.MaxTotalInputs != 0 {
		t.Errorf("recon input limits = %d/%d, want 0/0 (never consulted)", recon.MaxInputsPerEndpoint, recon.MaxTotalInputs)
	}
}

func TestRegistry_GetUnknownProfile(t *testing.T) {
	if _, ok := DefaultRegistry().Get("nonexistent"); ok {
		t.Fatal("Get returned ok=true for a profile that does not exist")
	}
}

func TestRegistry_DefaultProfileIsRecon(t *testing.T) {
	if DefaultProfileName != "recon" {
		t.Fatalf("DefaultProfileName = %q, want \"recon\"", DefaultProfileName)
	}
	if _, ok := DefaultRegistry().Get(DefaultProfileName); !ok {
		t.Fatal("DefaultProfileName does not name a registered profile")
	}
}

// TestRegistry_ReconProfile_CrawlerAndDetectionBothDisabled is the
// core safety property of the "recon" profile -- Phase 3.12 task's
// explicit requirement that it never becomes more active than
// sakanner's own pre-existing crawler-disabled default.
func TestRegistry_ReconProfile_CrawlerAndDetectionBothDisabled(t *testing.T) {
	p, ok := DefaultRegistry().Get("recon")
	if !ok {
		t.Fatal("recon profile not found")
	}
	if p.CrawlEnabled {
		t.Error("recon profile has CrawlEnabled = true, want false")
	}
	if p.DetectionEnabled {
		t.Error("recon profile has DetectionEnabled = true, want false")
	}
	if p.VerificationEnabled {
		t.Error("recon profile has VerificationEnabled = true, want false")
	}
	if p.EvidenceEnabled {
		t.Error("recon profile has EvidenceEnabled = true, want false")
	}
}

func TestRegistry_WebAndDeepProfiles_CrawlerAndDetectionBothEnabled(t *testing.T) {
	for _, name := range []string{"web", "deep"} {
		p, ok := DefaultRegistry().Get(name)
		if !ok {
			t.Fatalf("%s profile not found", name)
		}
		if !p.CrawlEnabled {
			t.Errorf("%s profile has CrawlEnabled = false, want true", name)
		}
		if !p.DetectionEnabled {
			t.Errorf("%s profile has DetectionEnabled = false, want true", name)
		}
	}
}

// TestRegistry_DeepProfile_MoreThanWeb_ButBounded checks Phase 3.12's
// exact requirement: deep is deeper than web (a real, meaningful
// difference), but every one of deep's own limits is still a finite,
// positive number -- never "unlimited."
func TestRegistry_DeepProfile_MoreThanWeb_ButBounded(t *testing.T) {
	web, _ := DefaultRegistry().Get("web")
	deep, _ := DefaultRegistry().Get("deep")

	if deep.CrawlMaxDepth <= web.CrawlMaxDepth {
		t.Errorf("deep.CrawlMaxDepth (%d) must exceed web's (%d)", deep.CrawlMaxDepth, web.CrawlMaxDepth)
	}
	if deep.CrawlMaxPages <= web.CrawlMaxPages {
		t.Errorf("deep.CrawlMaxPages (%d) must exceed web's (%d)", deep.CrawlMaxPages, web.CrawlMaxPages)
	}
	for _, p := range []Profile{web, deep} {
		if p.CrawlMaxDepth <= 0 {
			t.Errorf("%s: CrawlMaxDepth must be positive, got %d", p.Name, p.CrawlMaxDepth)
		}
		if p.CrawlMaxPages <= 0 {
			t.Errorf("%s: CrawlMaxPages must be positive, got %d", p.Name, p.CrawlMaxPages)
		}
		if p.ScanTimeout <= 0 {
			t.Errorf("%s: ScanTimeout must be positive (bounded), got %v", p.Name, p.ScanTimeout)
		}
		if p.StageTimeout <= 0 {
			t.Errorf("%s: StageTimeout must be positive (bounded), got %v", p.Name, p.StageTimeout)
		}
		if p.DetectionConcurrency <= 0 {
			t.Errorf("%s: DetectionConcurrency must be positive, got %d", p.Name, p.DetectionConcurrency)
		}
	}
}

// TestRegistry_EveryProfile_HasBoundedResourceLimits is the general
// form of the above, applied to ALL profiles including "recon" --
// task's explicit "no unlimited values" for every profile, not just
// deep.
func TestRegistry_EveryProfile_HasBoundedResourceLimits(t *testing.T) {
	for _, p := range DefaultRegistry().List() {
		if p.CrawlMaxDepth < 0 {
			t.Errorf("%s: negative CrawlMaxDepth %d", p.Name, p.CrawlMaxDepth)
		}
		if p.CrawlMaxPages < 0 {
			t.Errorf("%s: negative CrawlMaxPages %d", p.Name, p.CrawlMaxPages)
		}
		if p.ScanTimeout <= 0 {
			t.Errorf("%s: ScanTimeout not positive/bounded: %v", p.Name, p.ScanTimeout)
		}
		if p.StageTimeout <= 0 {
			t.Errorf("%s: StageTimeout not positive/bounded: %v", p.Name, p.StageTimeout)
		}
		if p.ResourceClass == "" {
			t.Errorf("%s: ResourceClass not set", p.Name)
		}
	}
}

// TestRegistry_Immutable: mutating a Profile value obtained from the
// registry must never affect a later Get/List call -- Registry.byName
// stores plain values (Go structs, not pointers), so each Get/List
// already returns an independent copy; this test pins that contract
// down explicitly since profile immutability (task's requirement) is
// safety-relevant.
func TestRegistry_Immutable(t *testing.T) {
	p, _ := DefaultRegistry().Get("web")
	p.CrawlEnabled = false
	p.CrawlMaxDepth = 999999

	again, _ := DefaultRegistry().Get("web")
	if !again.CrawlEnabled {
		t.Error("mutating a returned Profile value affected a later Get call (CrawlEnabled)")
	}
	if again.CrawlMaxDepth == 999999 {
		t.Error("mutating a returned Profile value affected a later Get call (CrawlMaxDepth)")
	}
}
