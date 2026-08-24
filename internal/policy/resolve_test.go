package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolve_ExplicitProfile_ReturnsThatProfilesSettings(t *testing.T) {
	for _, name := range []string{"recon", "web", "deep"} {
		eff, err := Resolve(name, ConfigView{})
		if err != nil {
			t.Fatalf("Resolve(%q): unexpected error: %v", name, err)
		}
		p, _ := DefaultRegistry().Get(name)
		if eff.ProfileName != p.Name {
			t.Errorf("Resolve(%q).ProfileName = %q, want %q", name, eff.ProfileName, p.Name)
		}
		if eff.CrawlEnabled != p.CrawlEnabled || eff.CrawlMaxDepth != p.CrawlMaxDepth || eff.CrawlMaxPages != p.CrawlMaxPages {
			t.Errorf("Resolve(%q) crawler settings do not match the profile", name)
		}
		if eff.DetectionEnabled != p.DetectionEnabled {
			t.Errorf("Resolve(%q).DetectionEnabled = %v, want %v", name, eff.DetectionEnabled, p.DetectionEnabled)
		}
	}
}

// TestResolve_ExplicitProfile_IgnoresConfig is the core "CLI profile >
// explicit configuration" precedence property: an explicit --profile
// wins even when the config file says something that contradicts it
// (task's "profile = recon, crawler.enabled = true" example must have
// deterministic, non-ambiguous behavior).
func TestResolve_ExplicitProfile_IgnoresConfig(t *testing.T) {
	eff, err := Resolve("recon", ConfigView{CrawlerEnabled: true, CrawlerMaxDepth: 99, CrawlerMaxPages: 999})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eff.CrawlEnabled {
		t.Error("--profile recon with crawler.enabled=true in config still resolved CrawlEnabled=true -- profile must win unconditionally")
	}
	if eff.DetectionEnabled {
		t.Error("--profile recon with crawler.enabled=true in config still resolved DetectionEnabled=true")
	}
	if eff.CrawlMaxDepth != 0 || eff.CrawlMaxPages != 0 {
		t.Errorf("--profile recon leaked config's crawl depth/pages: got depth=%d pages=%d", eff.CrawlMaxDepth, eff.CrawlMaxPages)
	}
}

// TestResolve_NoProfile_ConfigCrawlerEnabled_PreservesLegacyBehavior
// is the "explicit configuration > default profile" precedence tier:
// an operator who already has crawler.enabled: true in their config
// and does not pass --profile must keep getting real crawling and
// detection, exactly as before Phase 3.12 -- profiles existing must
// not silently downgrade that.
func TestResolve_NoProfile_ConfigCrawlerEnabled_PreservesLegacyBehavior(t *testing.T) {
	eff, err := Resolve("", ConfigView{CrawlerEnabled: true, CrawlerMaxDepth: 7, CrawlerMaxPages: 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !eff.CrawlEnabled {
		t.Error("no --profile with crawler.enabled=true in config resolved CrawlEnabled=false -- legacy behavior broken")
	}
	if eff.CrawlMaxDepth != 7 || eff.CrawlMaxPages != 42 {
		t.Errorf("config's own crawl depth/pages not honored: got depth=%d pages=%d, want depth=7 pages=42", eff.CrawlMaxDepth, eff.CrawlMaxPages)
	}
	if !eff.DetectionEnabled {
		t.Error("no --profile with crawler.enabled=true in config resolved DetectionEnabled=false -- legacy behavior broken")
	}
}

// TestResolve_NoProfile_NoConfigCrawler_FallsBackToReconDefault is the
// third precedence tier: nothing explicit given at all -> the "recon"
// default profile applies, matching sakanner's pre-existing
// crawler-disabled-by-default behavior.
func TestResolve_NoProfile_NoConfigCrawler_FallsBackToReconDefault(t *testing.T) {
	eff, err := Resolve("", ConfigView{CrawlerEnabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eff.CrawlEnabled {
		t.Error("no --profile, crawler.enabled=false in config: resolved CrawlEnabled=true, want false (recon default)")
	}
	if eff.DetectionEnabled {
		t.Error("no --profile, crawler.enabled=false in config: resolved DetectionEnabled=true, want false (recon default)")
	}
	if !strings.Contains(eff.ProfileName, "recon") {
		t.Errorf("ProfileName = %q, want it to name the recon default", eff.ProfileName)
	}
}

func TestResolve_UnknownProfile_ReturnsUnknownProfileError(t *testing.T) {
	_, err := Resolve("bogus-profile-xyz", ConfigView{})
	if err == nil {
		t.Fatal("Resolve with an unknown profile name returned no error")
	}
	upe, ok := err.(*UnknownProfileError)
	if !ok {
		t.Fatalf("error is not *UnknownProfileError: %v (%T)", err, err)
	}
	if upe.Name != "bogus-profile-xyz" {
		t.Errorf("UnknownProfileError.Name = %q, want %q", upe.Name, "bogus-profile-xyz")
	}
	if len(upe.Available) != 3 {
		t.Errorf("UnknownProfileError.Available = %v, want 3 entries", upe.Available)
	}
}

// TestUnknownProfileError_MatchesRequiredWording pins the exact error
// text the task specifies: `unknown scan profile "something"` followed
// by an "Available profiles:" list.
func TestUnknownProfileError_MatchesRequiredWording(t *testing.T) {
	err := &UnknownProfileError{Name: "something", Available: []string{"deep", "recon", "web"}}
	msg := err.Error()
	if !strings.Contains(msg, `unknown scan profile "something"`) {
		t.Errorf("error message missing required phrase: %q", msg)
	}
	if !strings.Contains(msg, "Available profiles:") {
		t.Errorf("error message missing required phrase: %q", msg)
	}
	for _, name := range []string{"deep", "recon", "web"} {
		if !strings.Contains(msg, name) {
			t.Errorf("error message missing profile name %q: %q", name, msg)
		}
	}
}

// TestResolve_Deterministic: calling Resolve twice with identical
// arguments must produce byte-identical results -- task's explicit
// determinism requirement, not dependent on time, randomness, or any
// other external state Resolve has no access to in the first place.
func TestResolve_Deterministic(t *testing.T) {
	cfg := ConfigView{CrawlerEnabled: true, CrawlerMaxDepth: 3, CrawlerMaxPages: 17}
	for _, profileFlag := range []string{"", "recon", "web", "deep"} {
		first, err := Resolve(profileFlag, cfg)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", profileFlag, err)
		}
		for i := 0; i < 50; i++ {
			again, err := Resolve(profileFlag, cfg)
			if err != nil {
				t.Fatalf("Resolve(%q) iteration %d: %v", profileFlag, i, err)
			}
			if !reflect.DeepEqual(first, again) {
				t.Fatalf("Resolve(%q) not deterministic: iteration %d differs:\n%+v\n%+v", profileFlag, i, first, again)
			}
		}
	}
}
