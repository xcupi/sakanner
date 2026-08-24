package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// These tests prove Prober does not hang indefinitely against a target
// that never responds or responds slowly -- Config.Timeout must bound
// every request attempt.

func TestProbe_NonResponsiveServer_DoesNotHangIndefinitely(t *testing.T) {
	block := make(chan struct{}) // closed only at the very end, after srv.Close()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		<-block
	}))
	// srv.Close() waits for in-flight handlers to return, so the blocked
	// handler goroutine must be released before Close() is called, not
	// after -- hence closing "block" first via explicit ordering below
	// rather than relying on LIFO defer order.
	defer func() {
		close(block)
		srv.Close()
	}()
	ip, port := testServerIPPort(t, srv)

	const cfgTimeout = 300 * time.Millisecond
	v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: cfgTimeout, MaxRedirects: 3}, nil)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.Probe(context.Background(), ip, port, ip.String())
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// Probe tries https then http, each bounded by cfgTimeout, so an
		// upper bound of 5x accounts for both attempts plus scheduling
		// slack without being a hair-trigger flaky assertion.
		if elapsed > 5*cfgTimeout {
			t.Errorf("Probe took %v against a non-responsive server, want well under %v", elapsed, 5*cfgTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Probe hung indefinitely against a non-responsive server")
	}
}

func TestProbe_SlowServer_TimesOutRatherThanHanging(t *testing.T) {
	const cfgTimeout = 200 * time.Millisecond
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(10 * cfgTimeout) // much slower than the configured timeout
		w.Write([]byte("too slow"))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: cfgTimeout, MaxRedirects: 3}, nil)

	start := time.Now()
	_, _, err := p.Probe(context.Background(), ip, port, ip.String())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Probe to fail/time out against a server far slower than the configured timeout")
	}
	if elapsed > 5*cfgTimeout {
		t.Errorf("Probe took %v, want well under %v (5x configured timeout)", elapsed, 5*cfgTimeout)
	}
}
