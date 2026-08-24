package openredirectactive

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
)

// --- Host safety -----------------------------------------------------------

// TestAdversarial_ProbeRequest_NeverChangesHost proves every probe's
// own dial target is always t's own host/IP/port, regardless of which
// redirect-destination representation was injected as the PARAMETER
// VALUE.
func TestAdversarial_ProbeRequest_NeverChangesHost(t *testing.T) {
	var sawHost string
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		vulnerableHandler(w, r)
	})

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	if _, err := New(testDestination).Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- an injected redirect destination must never change the scanner's own dial target", sawHost, tgt.Host)
	}
}

// TestAdversarial_ConfiguredDestination_NeverActuallyDialed proves the
// scanner's own transport never dials the configured attacker
// destination -- CheckRedirect must stop the chain via
// http.ErrUseLastResponse BEFORE any connection is attempted. Uses a
// REAL, listening canary server as the destination (denied by scope)
// so an accidental dial would be directly observable, not just
// inferred from a fast test.
func TestAdversarial_ConfiguredDestination_NeverActuallyDialed(t *testing.T) {
	var hits int64
	// A distinct loopback IP (not 127.0.0.1, which srv itself uses) --
	// hostConditionalValidator checks hostnames, so the canary must
	// have a genuinely different one to be denied realistically.
	canaryListener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.9", "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	canary := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt64(&hits, 1)
		fmt.Fprint(w, "should never be reached")
	}))
	canary.Listener.Close()
	canary.Listener = canaryListener
	canary.Start()
	defer canary.Close()

	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", vulnerableHandler)

	destination := canary.URL + "/marker"
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{}) // canary's own host is NOT in allowedHosts
	result, err := New(destination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (the Location header alone is sufficient proof)", result.Outcome)
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("SECURITY: the configured out-of-scope destination was actually dialed %d time(s) -- it must only ever be inspected via the Location header, never connected to", hits)
	}
}

// --- Redirect chains ---------------------------------------------------

func TestDetect_RedirectChain_ThroughInScopeHop_Finding(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		next := r.FormValue("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		nethttp.Redirect(w, r, "/hop2?next="+next, nethttp.StatusFound)
	})
	mux.HandleFunc("/hop2", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, r.URL.Query().Get("next"), nethttp.StatusFound)
	})

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{MaxRedirects: 5})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (a 2-hop chain through an in-scope intermediate, ending out of scope, is still genuinely vulnerable)", result.Outcome)
	}
	f := result.Findings[0]
	if len(f.Evidence) != 2 {
		t.Errorf("len(Evidence) = %d, want 2", len(f.Evidence))
	}
}

func TestDetect_RedirectChain_StaysInScope_NoFinding(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		next := r.FormValue("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		nethttp.Redirect(w, r, "/hop2", nethttp.StatusFound)
	})
	mux.HandleFunc("/hop2", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "/dashboard", nethttp.StatusFound)
	})
	mux.HandleFunc("/dashboard", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("dashboard"))
	})

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{MaxRedirects: 5})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a redirect chain that stays entirely in scope was flagged")
	}
}

// --- Same-host, different-port ------------------------------------------

// TestDetect_SameHostDifferentPort_NoFinding proves a redirect to the
// SAME hostname on a DIFFERENT port -- in-scope per
// scope.Validator.CheckHost (hostname-only) -- is never reported as an
// open-redirect finding by this detector: it simply never matches the
// operator-configured destination, a structurally separate concern
// from whether the underlying client is ALLOWED to follow it.
func TestDetect_SameHostDifferentPort_NoFinding(t *testing.T) {
	host := "127.0.0.1"
	otherListener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	otherSrv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("other port"))
	}))
	otherSrv.Listener.Close()
	otherSrv.Listener = otherListener
	otherSrv.Start()
	defer otherSrv.Close()

	mainListener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := nethttp.NewServeMux()
	mainSrv := httptest.NewUnstartedServer(mux)
	mainSrv.Listener.Close()
	mainSrv.Listener = mainListener
	mainSrv.Start()
	defer mainSrv.Close()

	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		next := r.FormValue("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		nethttp.Redirect(w, r, otherSrv.URL+"/", nethttp.StatusFound)
	})

	tgt := targetFor(t, mainSrv, "next", "query", "GET")
	// Allow BOTH hosts (same hostname, different port -- scope is
	// hostname-based) to prove the underlying client CAN follow this
	// hop, and that this detector still correctly does not flag it.
	v := &hostConditionalValidator{allowedHosts: map[string]bool{host: true}}
	x := detection.NewExecutor(v, dns.NewFakeResolver(), detection.ExecutorConfig{MaxRedirects: 5})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a same-host, different-port redirect was flagged as the configured out-of-scope destination")
	}
}

// --- Concurrency / cancellation / resource bounds -------------------------

func TestAdversarial_ConcurrentDetects_NoCrossContamination(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", vulnerableHandler)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "next", "query", "GET")
			x := newExecutor(srv, detection.ExecutorConfig{})
			result, err := New(testDestination).Detect(context.Background(), tgt, x)
			if err != nil {
				errs <- fmt.Sprintf("goroutine %d: Detect error: %v", i, err)
				return
			}
			if result.Outcome != detection.OutcomeFinding {
				errs <- fmt.Sprintf("goroutine %d: Outcome = %s, want finding", i, result.Outcome)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestDetect_ContextCancelled_ReturnsPromptlyNoFinding(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "some response")
	})

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	result, err := New(testDestination).Detect(ctx, tgt, x)
	if err == nil {
		t.Fatal("expected a context-cancellation/timeout error")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a cancelled context must never produce a finding")
	}
}

// TestDetect_RequestCount_Bounded proves the total number of requests
// issued per eligible target is small and bounded: 1 baseline + up to
// 3 wire variants for query/form, never unbounded.
func TestDetect_RequestCount_Bounded(t *testing.T) {
	var hits int64
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt64(&hits, 1)
		w.Write([]byte("never redirects"))
	})

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	if _, err := New(testDestination).Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if hits != 4 {
		t.Errorf("hits = %d, want exactly 4 (1 baseline + 3 wire variants, none confirming)", hits)
	}
}

// --- Misconfiguration ----------------------------------------------------

func TestAdversarial_InvalidDestination_NeverConfirms(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", vulnerableHandler)

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New("not-a-valid-url-no-host").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Fatalf("Outcome = %s, want skipped for a destination with no host", result.Outcome)
	}
}
