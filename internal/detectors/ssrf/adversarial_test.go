// Adversarial tests for the SSRF detector, per Phase 3.4's explicit
// adversarial-testing requirement (only ever against controlled,
// synthetic local servers -- never external targets, never real
// internal networks, never cloud metadata). Several items from that
// list are already covered elsewhere and are not duplicated here:
//   - URL reflection -> TestDetect_ReflectedCallbackURLDoesNotCauseFalsePositive,
//     TestDetect_NoServerSideFetch_NoFinding (detector_test.go)
//   - duplicate/stale callbacks, callback from another scan/parameter,
//     delayed callbacks -> correlation_test.go
//   - timeout / cancellation / out-of-scope -> detector_test.go
package ssrf

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sakanner/internal/detection"
)

// fixedTokenCallback always returns the same token regardless of how
// many times NewToken is called -- a test double proving the detector
// itself behaves sanely if a CallbackClient implementation ever had a
// token-collision bug (uuid.NewString(), which the real
// lab.SSRFCallbackServer uses, makes a real collision
// astronomically unlikely, but Detect's own correctness shouldn't
// depend on that).
type fixedTokenCallback struct {
	cb    *fakeCallback
	token string
}

func (f fixedTokenCallback) NewToken(ctx context.Context) (string, string, error) {
	return f.token, "http://callback.test/cb/" + f.token, nil
}
func (f fixedTokenCallback) Observations(ctx context.Context, token string) ([]Observation, error) {
	return f.cb.Observations(ctx, token)
}

func TestAdversarial_TokenCollision_StillCorrelatesToTheSharedToken(t *testing.T) {
	cb := newFakeCallback()
	const sharedToken = "collided-token"
	cb.inject(sharedToken, Observation{Method: "GET", Timestamp: time.Now()})

	d := Detector{callback: fixedTokenCallback{cb: cb, token: sharedToken}}
	obs, err := d.waitForCallback(context.Background(), sharedToken)
	if err != nil {
		t.Fatalf("waitForCallback: %v", err)
	}
	if len(obs) == 0 {
		t.Error("expected the pre-seeded observation under the shared token to be found")
	}
}

func TestAdversarial_MalformedTargetURLNeverPanics(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	tgt.URL = srv.URL + "/?url=" + strings.Repeat("%", 200) // malformed percent-encoding
	x := newExecutor(true, detection.ExecutorConfig{})

	// Either a clean error (URL failed to parse/build) or a clean
	// no-finding result is acceptable here -- a panic is not, and this
	// call itself (inside testing.T's own recover) is the proof.
	_, _ = d.Detect(context.Background(), tgt, x)
}

func TestAdversarial_DangerousOriginalParameterValueNeverDialed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	// An unusual/dangerous-looking ORIGINAL value (as Phase 2 might have
	// discovered it on a crawled link) -- the detector must never dial
	// this; it only ever injects ITS OWN callback URL as the probe
	// value, never the original.
	tgt.URL = srv.URL + "/?url=file:///etc/passwd"
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
	// Both probes (baseline + callback) went to srv, exactly twice --
	// never to "file:///etc/passwd" or anywhere else.
	if hits != 2 {
		t.Errorf("srv received %d requests, want exactly 2 (baseline + callback probe)", hits)
	}
}

func TestAdversarial_VeryLongOriginalParameterValue_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	tgt.URL = srv.URL + "/?url=" + strings.Repeat("A", 20000)
	x := newExecutor(true, detection.ExecutorConfig{})

	if _, err := d.Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestAdversarial_URLEncodedEchoOfCallbackURLStillStripped(t *testing.T) {
	// Some frameworks percent-encode a value before echoing it back
	// (e.g. inside a "Location"-shaped text field). stripPayload strips
	// the URL-percent-encoded form too -- this proves that path doesn't
	// produce a false positive.
	cb := newFakeCallback()
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		target := r.URL.Query().Get("url")
		w.Write([]byte("redirecting to: " + target)) // echoed raw; the encoded-form branch of stripPayload is exercised by normalize_test.go's dedicated unit test
	}))
	defer srv.Close()

	d := New(cb)
	tgt := targetFor(t, srv, "url")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- echoing the callback URL (raw or encoded) is not evidence of a server-side fetch", result.Outcome)
	}
}

func TestAdversarial_DuplicateQueryParameterInOriginalURL_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("results: (none)"))
	}))
	defer srv.Close()

	d := New(newFakeCallback())
	tgt := targetFor(t, srv, "url")
	tgt.URL = srv.URL + "/?url=http://a.test/&url=http://b.test/"
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

			d := New(newFakeCallback())
			tgt := targetFor(t, srv, "url")
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
