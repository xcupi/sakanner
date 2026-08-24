package ssrf

import (
	"context"
	"time"
)

// Observation is one recorded hit against a callback URL: a real,
// out-of-band request the callback service received, presumably (once
// correlated by token) from a target application performing the
// server-side request this detector is trying to prove exists.
type Observation struct {
	Method     string
	Path       string
	RemoteAddr string
	Timestamp  time.Time
}

// CallbackClient is how this detector obtains a fresh, correlatable
// out-of-band callback URL and later checks whether anything hit it.
//
// In production this would be backed by an operator-configured,
// network-reachable callback/collaborator service -- sakanner ships no
// such infrastructure today (see docs/phase-3-4-ssrf.md "Callback
// architecture" for why), so productionRegistry()
// (cmd/scanner/detectors.go) does not register this detector yet,
// mirroring exactly how Phase 3.1 documented its own then-unwired
// DetectionConfig. In the Phase 3 Test Lab,
// lab.SSRFCallbackServer implements this interface directly, so
// the real Detector below is exercised against a real, local,
// non-forwarding HTTP server -- not a mock.
type CallbackClient interface {
	// NewToken returns a fresh, unique correlation token and the full
	// callback URL a probe should inject to trigger it. Every call
	// returns a distinct token, even for the same target/parameter --
	// correlation is per-probe, never reused.
	NewToken(ctx context.Context) (token, callbackURL string, err error)

	// Observations returns every request the callback service has
	// recorded for token so far -- an empty, non-nil-error result means
	// "no callback observed yet," not "no such token."
	Observations(ctx context.Context, token string) ([]Observation, error)
}
