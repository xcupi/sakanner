package orchestrator

import (
	"testing"

	"sakanner/internal/auth"
	"sakanner/internal/orchestration"
)

// TestBuildResult_NoAuthSession_ReportsUnauthenticated is task section
// 7's "scan completed without authentication" case: the default for
// every caller (including every pre-Phase-3.14 one) that supplies no
// Options.AuthSession at all.
func TestBuildResult_NoAuthSession_ReportsUnauthenticated(t *testing.T) {
	o := &Orchestrator{}
	state := NewScanState("scan-1", "target")
	state.Start()
	state.Finish(StatusCompleted)

	result := o.buildResult("scan-1", "target", "", nil, state, ReconSummary{}, InputSummary{}, CrawlSummary{}, 0, false, DetectorSummary{}, nil)
	if result.AuthState != auth.StateUnauthenticated {
		t.Errorf("AuthState = %s, want UNAUTHENTICATED", result.AuthState)
	}
	if result.AuthProfile != "" {
		t.Errorf("AuthProfile = %q, want empty", result.AuthProfile)
	}
	if result.AuthenticatedRequests != 0 || result.SessionExpired {
		t.Errorf("AuthenticatedRequests/SessionExpired = %d/%v, want 0/false for a scan with no auth session", result.AuthenticatedRequests, result.SessionExpired)
	}
	if result.CrawlSummary != (CrawlSummary{}) {
		t.Errorf("CrawlSummary = %+v, want zero value", result.CrawlSummary)
	}
}

// TestBuildResult_CrawlSummaryAndAuthCounters_PassedThroughVerbatim is
// Phase 3.15's own extension: buildResult must carry CrawlSummary/
// AuthenticatedRequests/SessionExpired through exactly as given, the
// same "no re-derivation, just carry the caller's own computed values"
// contract ReconSummary/InputSummary already follow.
func TestBuildResult_CrawlSummaryAndAuthCounters_PassedThroughVerbatim(t *testing.T) {
	o := &Orchestrator{}
	state := NewScanState("scan-3", "target")
	state.Start()
	state.Finish(StatusCompleted)

	crawlSum := CrawlSummary{PublicURLs: 5, AuthenticatedURLs: 12, AuthenticatedEndpoints: 20}
	result := o.buildResult("scan-3", "target", "", nil, state, ReconSummary{}, InputSummary{}, crawlSum, 37, true, DetectorSummary{}, nil)
	if result.CrawlSummary != crawlSum {
		t.Errorf("CrawlSummary = %+v, want %+v", result.CrawlSummary, crawlSum)
	}
	if result.AuthenticatedRequests != 37 {
		t.Errorf("AuthenticatedRequests = %d, want 37", result.AuthenticatedRequests)
	}
	if !result.SessionExpired {
		t.Error("SessionExpired = false, want true")
	}
}

// TestBuildResult_WithAuthSession_ReportsProfileAndState is the
// "authenticated scan completed successfully" / "authentication
// attempted and failed" distinction: buildResult reflects the
// Session's OWN State verbatim, never reinterpreting it.
func TestBuildResult_WithAuthSession_ReportsProfileAndState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state auth.State
	}{
		{"authenticated", auth.StateAuthenticated},
		{"failed", auth.StateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &Orchestrator{}
			state := NewScanState("scan-2", "target")
			state.Start()
			state.Finish(StatusCompleted)

			sess := &auth.Session{ProfileName: "lab-user", State: tc.state}
			result := o.buildResult("scan-2", "target", "", sess, state, ReconSummary{}, InputSummary{}, CrawlSummary{}, 0, false, DetectorSummary{}, nil)
			if result.AuthState != tc.state {
				t.Errorf("AuthState = %s, want %s", result.AuthState, tc.state)
			}
			if result.AuthProfile != "lab-user" {
				t.Errorf("AuthProfile = %q, want lab-user", result.AuthProfile)
			}
		})
	}
}

// TestBuildResult_IdentityDistinctFromAuthProfile is Phase 3.16's own
// test: Result.Identity (the configured IDENTITY name) and
// Result.AuthProfile (the underlying auth PROFILE name) must be
// reported independently -- task section 2's "do not collapse these
// concepts" applied to the final Result, not just the config model.
func TestBuildResult_IdentityDistinctFromAuthProfile(t *testing.T) {
	o := &Orchestrator{}
	state := NewScanState("scan-id-test", "target")
	state.Start()
	state.Finish(StatusCompleted)

	sess := &auth.Session{ProfileName: "customer-login", IdentityName: "account-a", State: auth.StateAuthenticated}
	result := o.buildResult("scan-id-test", "target", "", sess, state, ReconSummary{}, InputSummary{}, CrawlSummary{}, 0, false, DetectorSummary{}, nil)
	if result.AuthProfile != "customer-login" {
		t.Errorf("AuthProfile = %q, want customer-login", result.AuthProfile)
	}
	if result.Identity != "account-a" {
		t.Errorf("Identity = %q, want account-a", result.Identity)
	}
	if result.AuthProfile == result.Identity {
		t.Fatal("AuthProfile and Identity must never be conflated")
	}
}

// TestBuildResult_BareAuthProfile_NoIdentity is the backward-
// compatible case: a session authenticated via --auth-profile (no
// --identity wrapper) has no IdentityName at all, so Result.Identity
// stays empty while AuthProfile is still populated -- matching Phase
// 3.14/3.15's exact pre-3.16 output.
func TestBuildResult_BareAuthProfile_NoIdentity(t *testing.T) {
	o := &Orchestrator{}
	state := NewScanState("scan-bare", "target")
	state.Start()
	state.Finish(StatusCompleted)

	sess := &auth.Session{ProfileName: "customer-login", State: auth.StateAuthenticated} // IdentityName left unset
	result := o.buildResult("scan-bare", "target", "", sess, state, ReconSummary{}, InputSummary{}, CrawlSummary{}, 0, false, DetectorSummary{}, nil)
	if result.AuthProfile != "customer-login" {
		t.Errorf("AuthProfile = %q, want customer-login", result.AuthProfile)
	}
	if result.Identity != "" {
		t.Errorf("Identity = %q, want empty for a bare --auth-profile session", result.Identity)
	}
}

// TestScanPipeline_NilOverrideAndSession_ReturnsSharedPipeline is a
// regression guard: every pre-Phase-3.14 call site passes (nil, nil)
// and must keep getting o.Pipeline back UNCHANGED (identity, not just
// equal), preserving the exact existing behavior/allocation pattern.
func TestScanPipeline_NilOverrideAndSession_ReturnsSharedPipeline(t *testing.T) {
	base := &orchestration.Pipeline{CrawlEnabled: true, CrawlMaxDepth: 2}
	o := &Orchestrator{Pipeline: base}
	got := o.scanPipeline(nil, nil)
	if got != base {
		t.Fatal("scanPipeline(nil, nil) must return the exact same *Pipeline instance, not a copy")
	}
}

// TestScanPipeline_SessionOnly_CopiesAndSetsAuthSession verifies a
// session-only call (no CrawlOverride) leaves every crawl setting
// untouched while attaching AuthSession to a COPY, never mutating the
// shared o.Pipeline -- task section 5's "concurrent authenticated
// scans are isolated."
func TestScanPipeline_SessionOnly_CopiesAndSetsAuthSession(t *testing.T) {
	base := &orchestration.Pipeline{CrawlEnabled: true, CrawlMaxDepth: 7, CrawlMaxPages: 9}
	o := &Orchestrator{Pipeline: base}
	sess := &auth.Session{ProfileName: "x", State: auth.StateAuthenticated}

	got := o.scanPipeline(nil, sess)
	if got == base {
		t.Fatal("scanPipeline must return a COPY when session is non-nil, not the shared Pipeline")
	}
	if got.AuthSession != sess {
		t.Error("AuthSession was not attached to the copy")
	}
	if got.CrawlEnabled != base.CrawlEnabled || got.CrawlMaxDepth != base.CrawlMaxDepth || got.CrawlMaxPages != base.CrawlMaxPages {
		t.Errorf("crawl settings changed with no CrawlOverride: got %+v, want matching base %+v", got, base)
	}
	if base.AuthSession != nil {
		t.Fatal("the SHARED o.Pipeline must never be mutated -- a concurrent scan with a different (or no) session would see this session leak in")
	}
}

// TestScanPipeline_OverrideAndSessionTogether confirms both mechanisms
// combine correctly in one copy (the common case: a "web"/"deep"
// profile scan that also authenticates).
func TestScanPipeline_OverrideAndSessionTogether(t *testing.T) {
	base := &orchestration.Pipeline{CrawlEnabled: false}
	o := &Orchestrator{Pipeline: base}
	sess := &auth.Session{ProfileName: "x", State: auth.StateAuthenticated}
	override := &CrawlSettings{Enabled: true, MaxDepth: 3, MaxPages: 5}

	got := o.scanPipeline(override, sess)
	if !got.CrawlEnabled || got.CrawlMaxDepth != 3 || got.CrawlMaxPages != 5 {
		t.Errorf("CrawlOverride not applied: %+v", got)
	}
	if got.AuthSession != sess {
		t.Error("AuthSession not applied alongside CrawlOverride")
	}
}
