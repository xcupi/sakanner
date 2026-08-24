package ports

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestScan_RateLimiterActuallyPacesDials proves the rate limiter passed
// to NewTCPConnectScanner genuinely paces dial attempts -- not just that
// it's wired into the constructor. Without pacing, 10 dials to a fast,
// always-refused local port would complete in well under 100ms; with a
// 5/sec limiter and burst 1, they must take close to (10-1)/5 = 1.8s.
func TestScan_RateLimiterActuallyPacesDials(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := portOf(t, l)
	l.Close()

	limiter := rate.NewLimiter(rate.Limit(5), 1) // 5/sec, burst 1
	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, time.Second, 10, limiter)

	ports := make([]int, 10)
	for i := range ports {
		ports[i] = closedPort // same closed port repeatedly; we're timing pacing, not port state
	}

	start := time.Now()
	results, err := scanner.Scan(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	count := 0
	for range results {
		count++
	}
	elapsed := time.Since(start)

	if count != len(ports) {
		t.Fatalf("got %d results, want %d", count, len(ports))
	}

	const wantMin = 1500 * time.Millisecond // (10-1)/5s = 1.8s expected; allow slack for burst/scheduling
	if elapsed < wantMin {
		t.Errorf("Scan of %d ports at 5/sec took %v, want >= %v -- rate limiter does not appear to be pacing dials", len(ports), elapsed, wantMin)
	}
	t.Logf("10 dials at 5/sec took %v (unpaced would be well under 100ms)", elapsed)
}

// TestScan_NoLimiterIsFast is the control: without a limiter, the same
// 10 dials complete quickly, confirming the slowdown above is genuinely
// attributable to the rate limiter and not some other bottleneck.
func TestScan_NoLimiterIsFast(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := portOf(t, l)
	l.Close()

	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, time.Second, 10, nil)
	ports := make([]int, 10)
	for i := range ports {
		ports[i] = closedPort
	}

	start := time.Now()
	results, err := scanner.Scan(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for range results {
	}
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("unlimited scan of %d closed-port dials took %v, want well under 1s", len(ports), elapsed)
	}
}
