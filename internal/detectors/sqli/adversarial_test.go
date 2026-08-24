// Adversarial tests for the SQL injection detector, per Phase 3.3's
// explicit adversarial-testing requirement. Several items from that
// list are already covered elsewhere and are not duplicated here:
//   - dynamic responses / unstable response lengths / generic errors ->
//     TestDetect_DynamicContentUnrelatedToParameter_NoFinding,
//     TestDetect_GenericErrorEverywhere_NoFinding (detector_test.go)
//   - database error text unrelated to the probe (appears in baseline
//     too) -> TestComputeSignals_ErrorSuppressedWhenBaselineAlreadyErrors
//     (classify_test.go)
//   - timeout / cancellation / out-of-scope -> detector_test.go's
//     TestDetect_Timeout_ReturnsError, TestDetect_ContextCancellation_ReturnsError,
//     TestDetect_CancellationDuringBaseline, TestDetect_OutOfScope_ReturnsErrorWithoutDialing
//   - out-of-scope redirects -> inherited from the unmodified
//     safedial/Executor layer, already covered by
//     lab's Phase 2/3 redirect-to-out-of-scope tests
//   - repeated identical scans -> TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate
//     (detector_test.go), TestEngine_RerunIsIdempotentViaDeduplication
//     (Phase 3.1, unchanged)
//   - a real, previously-unknown false positive (reflected parameters
//     unrelated to SQL) was found via this exact kind of broad
//     adversarial testing against the real lab -- see
//     TestComputeSignals_NoFalsePositiveWhenPayloadEchoedRaw and
//     docs/phase-3-3-acceptance-test.md "Adversarial testing"
package sqli

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

func TestAdversarial_MalformedVeryLongParameterValue_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	// The ORIGINAL discovered value (before any probe substitutes it) is
	// adversarially long and control-character-laden -- this must never
	// reach the detector's own request-building logic in a way that
	// panics, since requestURL only ever substitutes t.Parameter's
	// value, never reads the original one.
	tgt.URL = srv.URL + "/?id=" + strings.Repeat("A%00%0d%0a", 5000)
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestAdversarial_DuplicateQueryParameterInOriginalURL_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	// The target's original URL (as BuildTargets might have produced
	// from a crawled link with a repeated query key) names "id" twice.
	tgt.URL = srv.URL + "/?id=1&id=2"
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive(t *testing.T) {
	for _, code := range []int{204, 301, 403, 429, 503} {
		code := code
		t.Run(nethttp.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				w.WriteHeader(code)
				w.Write([]byte("results: (none)"))
			}))
			defer srv.Close()

			d := New()
			tgt := targetFor(t, srv, "id")
			x := newExecutor(true, detection.ExecutorConfig{})

			result, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if result.Outcome != detection.OutcomeNoFinding {
				t.Errorf("Outcome = %v, want OutcomeNoFinding -- identical behavior regardless of status code must not be flagged", result.Outcome)
			}
		})
	}
}

func TestAdversarial_EncodedParameterValueRoundTrips(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	// A double-encoded original value.
	tgt.URL = srv.URL + "/?id=%2527%2520OR%25201%3D1"
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

func TestAdversarial_EmptyResponseBody_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// no body at all
	}))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "id")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped && result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeSkipped or OutcomeNoFinding for an empty body", result.Outcome)
	}
}
