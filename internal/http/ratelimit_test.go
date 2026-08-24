package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"sakanner/internal/dns"
)

// TestProbe_RateLimiterActuallyPacesRequests proves the rate limiter
// passed to NewProber genuinely paces requests, mirroring the same proof
// done for the port scanner.
func TestProbe_RateLimiterActuallyPacesRequests(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
	limiter := rate.NewLimiter(rate.Limit(5), 1) // 5/sec, burst 1
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 5 * time.Second, MaxRedirects: 3}, limiter)

	const n = 6
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, _, err := p.Probe(context.Background(), ip, port, ip.String()); err != nil {
			t.Fatalf("Probe %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	const wantMin = 800 * time.Millisecond // (6-1)/5s = 1s expected; allow slack
	if elapsed < wantMin {
		t.Errorf("%d probes at 5/sec took %v, want >= %v -- rate limiter does not appear to be pacing requests", n, elapsed, wantMin)
	}
	t.Logf("%d probes at 5/sec took %v", n, elapsed)
}
