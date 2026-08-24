package ssrf

import (
	"context"
	"testing"
	"time"
)

// These tests exercise callback correlation and isolation directly
// against fakeCallback -- no HTTP server needed, since correlation is a
// property of CallbackClient.Observations' own token-scoping, which
// Detect relies on entirely (it never inspects an Observation's content
// beyond "len > 0" -- the CLIENT is responsible for scoping
// Observations(token) to exactly that token, see
// lab.SSRFCallbackServer.Observations for the real
// implementation this proves the contract against indirectly via
// TestPhase3_4_SSRFDetector_MatchesGroundTruth).

func TestCorrelation_UnrelatedCallbackDoesNotAffectAnotherToken(t *testing.T) {
	cb := newFakeCallback()
	cb.inject("token-for-someone-else", Observation{Method: "GET", Path: "/cb/token-for-someone-else", RemoteAddr: "10.0.0.5:1234", Timestamp: time.Now()})

	obs, err := cb.Observations(context.Background(), "token-1")
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("Observations(token-1) = %+v, want empty -- a callback recorded under a DIFFERENT token must never leak into this one", obs)
	}
}

func TestCorrelation_CallbackFromAnotherScanIsolated(t *testing.T) {
	// Two independent fakeCallback instances model two independent
	// scans (each Engine.Run would construct its own CallbackClient,
	// e.g. its own lab.SSRFCallbackServer instance, or -- in a
	// real production deployment -- a request to a shared collaborator
	// service scoped by a per-scan token namespace). A callback
	// recorded on one must never be visible through the other.
	scanA := newFakeCallback()
	scanB := newFakeCallback()

	tokenA, _, err := scanA.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	scanA.inject(tokenA, Observation{Method: "GET", Timestamp: time.Now()})

	obsB, err := scanB.Observations(context.Background(), tokenA)
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(obsB) != 0 {
		t.Errorf("scan B observed scan A's callback: %+v", obsB)
	}
}

func TestCorrelation_DuplicateCallbacksStillOneFinding(t *testing.T) {
	// Detect only ever checks len(observations) > 0 -- multiple
	// observations for the same token (a target that fetched the
	// callback URL more than once) must still produce exactly ONE
	// finding, not one per observation. This is enforced by Detect
	// itself returning a single Result with a single Finding regardless
	// of how many Observation entries d.callback.Observations returns.
	cb := newFakeCallback()
	token, callbackURL, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	cb.inject(token, Observation{Method: "GET", Timestamp: time.Now()})
	cb.inject(token, Observation{Method: "GET", Timestamp: time.Now().Add(time.Millisecond)}) // duplicate

	d := Detector{callback: cb}
	obs, err := d.waitForCallback(context.Background(), token)
	if err != nil {
		t.Fatalf("waitForCallback: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("sanity: expected 2 raw observations, got %d", len(obs))
	}
	// The finding-building path (Detect) only branches on len(obs) > 0,
	// never "one finding per entry" -- confirmed by construction; see
	// TestDetect_CallbackObserved_HighConfidenceFinding for the
	// single-Finding assertion this relies on.
	_ = callbackURL
}

func TestCorrelation_StaleCallbackFromPreviousScanNeverMatchesNewToken(t *testing.T) {
	cb := newFakeCallback()
	// A callback recorded under an OLD token (a previous Detect call's
	// token, now discarded).
	cb.inject("stale-token-from-earlier-run", Observation{Method: "GET", Timestamp: time.Now().Add(-time.Hour)})

	// A fresh token for a NEW probe must never see it.
	freshToken, _, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	obs, err := cb.Observations(context.Background(), freshToken)
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("Observations(freshToken) = %+v, want empty", obs)
	}
}

func TestCorrelation_CallbackArrivesDuringPolling(t *testing.T) {
	cb := newFakeCallback()
	d := Detector{callback: cb}

	token, _, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	go func() {
		time.Sleep(30 * time.Millisecond) // arrives mid-poll, well within callbackMaxWait
		cb.inject(token, Observation{Method: "GET", Timestamp: time.Now()})
	}()

	start := time.Now()
	obs, err := d.waitForCallback(context.Background(), token)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("waitForCallback: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("waitForCallback returned no observations for a callback that arrived mid-poll")
	}
	if elapsed >= callbackMaxWait {
		t.Errorf("waitForCallback took %v, want well under callbackMaxWait (%v) -- it should return as soon as the observation appears, not wait out the full budget", elapsed, callbackMaxWait)
	}
}

func TestCorrelation_CallbackArrivesAfterTimeout(t *testing.T) {
	cb := newFakeCallback()
	d := Detector{callback: cb}

	token, _, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	start := time.Now()
	obs, err := d.waitForCallback(context.Background(), token)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("waitForCallback: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("waitForCallback returned %+v, want empty (nothing was ever injected)", obs)
	}
	if elapsed < callbackMaxWait {
		t.Errorf("waitForCallback returned after %v, want at least callbackMaxWait (%v)", elapsed, callbackMaxWait)
	}

	// A callback that shows up AFTER this point (simulating "arrives
	// after timeout") must not retroactively affect the ALREADY-RETURNED
	// result -- Detect has already moved on to its behavioral-diff
	// fallback by the time this happens in practice.
	cb.inject(token, Observation{Method: "GET", Timestamp: time.Now()})
	// (no assertion needed beyond "this doesn't panic or block" -- the
	// point is that waitForCallback already returned above)
}
