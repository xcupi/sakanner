package cmdinjectionactive

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
)

// --- Host safety -----------------------------------------------------------

// TestAdversarial_ProbeRequest_NeverChangesHost proves every probe's
// own dial target is always t's own host/IP/port, regardless of which
// separator/payload was injected as the PARAMETER VALUE -- mirroring
// the identical, already-established host-safety argument every other
// active detector's own adversarial suite makes.
func TestAdversarial_ProbeRequest_NeverChangesHost(t *testing.T) {
	var sawHost string
	srv := httptest.NewServer(vulnerableHandlerRecordingHost(unixPattern, &sawHost))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- an injected payload value must never change the scanner's own dial target", sawHost, tgt.Host)
	}
}

func vulnerableHandlerRecordingHost(pattern *regexp.Regexp, sawHost *string) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		*sawHost = r.Host
		host := r.URL.Query().Get("host")
		if m := pattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response", host)
	}
}

// --- Concurrent scans / independent markers --------------------------------

// TestAdversarial_ConcurrentDetects_IndependentMarkersNoCrossContamination
// runs many concurrent Detect calls against the SAME vulnerable
// server, proving each probe's own freshly generated token is never
// confused with another concurrent probe's -- the server itself is
// stateless (pure regex match per request), so this specifically
// proves the DETECTOR side never mixes up which token belongs to
// which in-flight request.
func TestAdversarial_ConcurrentDetects_IndependentMarkersNoCrossContamination(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler(unixPattern))
	defer srv.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
			x := newExecutor(true, detection.ExecutorConfig{})
			result, err := New().Detect(context.Background(), tgt, x)
			if err != nil {
				errs <- fmt.Sprintf("goroutine %d: Detect error: %v", i, err)
				return
			}
			if result.Outcome != detection.OutcomeFinding {
				errs <- fmt.Sprintf("goroutine %d: Outcome = %s, want finding", i, result.Outcome)
				return
			}
			f := result.Findings[0]
			if len(f.Evidence) != 2 {
				errs <- fmt.Sprintf("goroutine %d: expected 2 evidence items, got %d", i, len(f.Evidence))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// --- Marker collision --------------------------------------------------

// TestAdversarial_BareMarkerPrefixWithoutExactToken_NeverConfirms proves
// a response containing the marker PREFIX followed by a DIFFERENT
// (stale/unrelated) token never confirms -- only an EXACT match of
// THIS probe's own token counts.
func TestAdversarial_BareMarkerPrefixWithoutExactToken_NeverConfirms(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Always returns the marker prefix followed by a FIXED, stale,
		// never-actually-issued token -- never this specific probe's own.
		fmt.Fprintf(w, "PING normal response\n%sstale-token-that-was-never-issued-by-this-probe", markerPrefix)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a stale/unrelated token following the marker prefix must never confirm a finding")
	}
}

// --- Cancellation --------------------------------------------------------

// TestDetect_ContextCancelled_ReturnsPromptlyNoFinding proves
// cancellation propagates cleanly -- no finding, an error returned,
// and (implicitly, since Detect returns rather than hanging) no
// goroutine/request left in flight.
func TestDetect_ContextCancelled_ReturnsPromptlyNoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "PING normal response")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	result, err := New().Detect(ctx, tgt, x)
	if err == nil {
		t.Fatal("expected a context-cancellation/timeout error")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a cancelled context must never produce a finding")
	}
}

// --- Resource bounds -------------------------------------------------------

// TestDetect_RequestCount_Bounded proves the total number of requests
// issued per eligible target is small and bounded (1 baseline + at
// most 4 variant probes = 5), never unbounded.
func TestDetect_RequestCount_Bounded(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprint(w, "PING normal response, never matches any grammar")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if hits != 5 {
		t.Errorf("hits = %d, want exactly 5 (1 baseline + 4 variant probes, none confirming)", hits)
	}
}
