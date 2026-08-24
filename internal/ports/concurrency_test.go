package ports

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/scope"
)

// trackingValidator allows every check but records the high-water mark
// of concurrent in-flight checks (each dial calls CheckResolved
// immediately before dialing, so this is a direct proxy for in-flight
// dial count) and holds briefly to widen the window in which concurrent
// goroutines can pile up, making the assertion meaningful rather than a
// coincidence of scheduling.
type trackingValidator struct {
	inFlight  int32
	highWater int32
	holdFor   time.Duration
}

func (v *trackingValidator) track() func() {
	cur := atomic.AddInt32(&v.inFlight, 1)
	for {
		hw := atomic.LoadInt32(&v.highWater)
		if cur <= hw {
			break
		}
		if atomic.CompareAndSwapInt32(&v.highWater, hw, cur) {
			break
		}
	}
	if v.holdFor > 0 {
		time.Sleep(v.holdFor)
	}
	return func() { atomic.AddInt32(&v.inFlight, -1) }
}

func (v *trackingValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	release := v.track()
	defer release()
	return scope.Decision{Allowed: true}, nil
}

func (v *trackingValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	release := v.track()
	defer release()
	return scope.Decision{Allowed: true}, nil
}

func (v *trackingValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	release := v.track()
	defer release()
	return scope.Decision{Allowed: true}, nil
}

// TestScan_TrueAggregateConcurrencyAcrossHosts proves the concurrency
// limit passed to NewTCPConnectScanner bounds the TRUE aggregate number
// of in-flight dials across every host scanned concurrently through the
// same Scanner instance -- not per-host independently, which would let
// (concurrency * concurrent hosts) dials run at once.
func TestScan_TrueAggregateConcurrencyAcrossHosts(t *testing.T) {
	const concurrencyLimit = 4
	const hostCount = 6
	const portsPerHost = 8

	v := &trackingValidator{holdFor: 15 * time.Millisecond}
	scanner := NewTCPConnectScanner(v, time.Second, concurrencyLimit, nil)

	ports := make([]int, portsPerHost)
	for i := range ports {
		ports[i] = 40000 + i // unused local ports; connections will simply be refused, which is fine -- we're measuring concurrency, not open/closed
	}

	var wg sync.WaitGroup
	for h := 0; h < hostCount; h++ {
		h := h
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := net.ParseIP("127.0.0.1")
			results, err := scanner.Scan(context.Background(), "127.0.0.1", ip, ports)
			if err != nil {
				t.Errorf("host %d: Scan: %v", h, err)
				return
			}
			for range results {
			}
		}()
	}
	wg.Wait()

	// Each Scan call does one CheckResolved pre-flight check before
	// spawning any per-port work -- a cheap, intentionally
	// non-semaphore-gated fail-fast gate, not a dial -- so up to
	// hostCount of those can legitimately overlap in addition to the
	// concurrencyLimit semaphore-gated per-port checks. That upper bound
	// (hostCount + concurrencyLimit = 10) is still sharply distinguishable
	// from the compounding bug this test targets, which would show
	// concurrency approaching hostCount * concurrencyLimit (24).
	const wantMax = hostCount + concurrencyLimit

	hw := atomic.LoadInt32(&v.highWater)
	if hw > wantMax {
		t.Errorf("observed high-water concurrent check count = %d, want <= %d -- per-port dial concurrency is not being bounded by a shared limit across hosts", hw, wantMax)
	}
	if hw == 0 {
		t.Fatal("high-water mark is 0 -- test did not actually observe any concurrent dials, so it proves nothing")
	}
	t.Logf("observed high-water concurrent check count: %d (per-host-fanout ceiling: %d, compounding-bug ceiling would be ~%d)", hw, wantMax, hostCount*concurrencyLimit)
}
