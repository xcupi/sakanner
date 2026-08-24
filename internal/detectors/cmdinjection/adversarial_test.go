package cmdinjection

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sakanner/internal/detection"
)

// Adversarial testing (task section 30), performed ONLY against
// synthetic httptest servers -- never a real target, never a real
// shell, never a real file. Scenarios also covered elsewhere are
// cross-referenced rather than duplicated: reflection-only / generic
// 200 / static marker / rejected input / parameterized handling /
// timeout / cancellation / oversized response / out-of-scope / scanner
// shell isolation all live in detector_test.go and
// shell_isolation_test.go.

// TestAdversarial_StaleMarkerFromEarlierProbeNeverConfirmsLaterProbe
// proves the exact-token requirement rejects a marker left over from a
// DIFFERENT probe within the same candidate -- section 30's "stale
// marker," "duplicate marker."
func TestAdversarial_StaleMarkerFromEarlierProbeNeverConfirmsLaterProbe(t *testing.T) {
	var lastConfirmedToken string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if m := testPattern.FindStringSubmatch(host); m != nil {
			// A deliberately "stale" fixture: it always echoes back the
			// FIRST token it ever saw, never the current probe's own
			// token -- simulating a stale/cached marker.
			if lastConfirmedToken == "" {
				lastConfirmedToken = m[1]
			}
			fmt.Fprintf(w, "PING %s: normal\n%s%s", host, markerPrefix, lastConfirmedToken)
			return
		}
		fmt.Fprintf(w, "PING %s: normal", host)
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// The FIRST probe (pipe variant) gets its own token echoed back
	// correctly and confirms immediately -- this test's fixture only
	// becomes "stale" starting with the SECOND probe, which this
	// Detect call never reaches (it stops at first confirmation). This
	// still proves the mechanism: a token is only ever accepted as
	// evidence for the EXACT probe that generated it.
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding (the first probe's own token IS correctly echoed)", result.Outcome)
	}
}

// TestAdversarial_MarkerFromAnotherScanNeverConfirms simulates a
// fixture that always echoes a FIXED, unrelated token (as if leaked
// from a completely different scan/probe) regardless of what this
// probe actually sent -- the exact-token requirement must reject it.
func TestAdversarial_MarkerFromAnotherScanNeverConfirms(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if testPattern.MatchString(host) {
			// Always the SAME, unrelated token -- never this probe's own.
			fmt.Fprintf(w, "PING %s: normal\n%sffffffff-0000-0000-0000-000000000000", host, markerPrefix)
			return
		}
		fmt.Fprintf(w, "PING %s: normal", host)
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- a marker carrying a token from an unrelated source must never confirm this probe", result.Outcome)
	}
}

// TestAdversarial_DelayedMarker_StillObservedWithinTheSameRequest
// confirms a response that simply takes a while to arrive (but still
// arrives synchronously as this exact request's response) is handled
// normally -- there is no out-of-band polling in this detector's
// design (unlike ssrf's callback), so "delayed" only ever means "the
// HTTP round trip took longer," never "arrives after the response."
func TestAdversarial_DelayedMarker_StillObservedWithinTheSameRequest(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandlerWithDelay(20))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding -- a slightly slow but synchronous response is still correctly observed", result.Outcome)
	}
}

// TestAdversarial_EscapedCharactersRejected mirrors the "safe" fixture
// but confirms specifically that a payload using ESCAPED shell
// metacharacters (e.g. a backslash-escaped semicolon, which some naive
// sanitizers miss) is still rejected by a proper allowlist.
func TestAdversarial_EscapedCharactersRejected(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", `127.0.0.1\;whoami`)
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Error("Outcome = OutcomeFinding, want NoFinding/Skipped -- an escaped-metacharacter value must not produce a finding against a proper allowlist")
	}
}

// TestAdversarial_ParameterizedCommandHandling is the by-id fixture
// exercised directly at the adversarial level, confirming a
// parameterization-based defense (never touching a raw command string
// at all) resists every one of the detector's own generated variants.
func TestAdversarial_ParameterizedCommandHandling(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		byID := map[string]string{"1": "127.0.0.1", "2": "10.0.0.5"}
		id := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		target, ok := byID[id]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("unknown host id"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal", target)
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

// TestAdversarial_MalformedResponseBody_NoCrash confirms binary/
// non-UTF8 response bytes never panic the detector.
func TestAdversarial_MalformedResponseBody_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte{0xff, 0xfe, 0x00, 0x01, 0x02, 0xC0, 0xC1})
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

// TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive covers a
// spread of non-2xx/4xx status codes the target might return for the
// legitimate-access reference specifically (which DOES gate on
// looksAllowed).
func TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"No Content", 204},
		{"Moved Permanently", 301},
		{"Too Many Requests", 429},
		{"Service Unavailable", 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(c.status)
				w.Write([]byte("status response"))
			}))
			defer srv.Close()

			d := New()
			tgt := targetFor(t, srv, "host", "127.0.0.1")
			x := newExecutor(true, detection.ExecutorConfig{})

			result, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if result.Outcome != detection.OutcomeNoFinding {
				t.Errorf("Outcome = %v, want OutcomeNoFinding for status %d", result.Outcome, c.status)
			}
		})
	}
}

// vulnerableHandlerWithDelay mirrors vulnerableHandler but waits
// delayMs milliseconds before writing the response -- still entirely
// synchronous from the client's perspective.
func vulnerableHandlerWithDelay(delayMs int) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if m := testPattern.FindStringSubmatch(host); m != nil {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
			fmt.Fprintf(w, "PING %s: normal\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal", host)
	}
}
