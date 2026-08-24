package ports

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/scope"
)

// fakeValidator lets tests control scope decisions directly without
// depending on internal/scope's rule-matching logic.
type fakeValidator struct {
	allowed bool
	calls   int32
}

func (f *fakeValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return f.check()
}

func (f *fakeValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return f.check()
}

func (f *fakeValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return f.check()
}

func (f *fakeValidator) check() (scope.Decision, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

// listenerWithCounter wraps net.Listen and counts accepted connections,
// used to prove that a denied scan makes zero dial attempts.
func listenerWithCounter(t *testing.T) (net.Listener, *int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var count int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&count, 1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l, &count
}

func portOf(t *testing.T, l net.Listener) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

func TestScan_AllowedFindsOpenPort(t *testing.T) {
	l, _ := listenerWithCounter(t)
	port := portOf(t, l)

	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, time.Second, 5, nil)
	results, err := scanner.Scan(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), []int{port, port + 50000})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var openCount, closedCount int
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected result error: %v", r.Error)
		}
		if r.Open {
			openCount++
			if r.Port != port {
				t.Errorf("open result for unexpected port %d", r.Port)
			}
		} else {
			closedCount++
		}
	}
	if openCount != 1 {
		t.Errorf("openCount = %d, want 1", openCount)
	}
	if closedCount != 1 {
		t.Errorf("closedCount = %d, want 1", closedCount)
	}
}

func TestScan_DeniedMakesZeroDialAttempts(t *testing.T) {
	l, acceptCount := listenerWithCounter(t)
	port := portOf(t, l)

	scanner := NewTCPConnectScanner(&fakeValidator{allowed: false}, time.Second, 5, nil)
	_, err := scanner.Scan(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), []int{port})
	if err == nil {
		t.Fatal("expected Scan to fail outright when the target IP itself is out of scope")
	}

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(acceptCount) != 0 {
		t.Errorf("acceptCount = %d, want 0 (denied scan must never dial)", atomic.LoadInt32(acceptCount))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	l, _ := listenerWithCounter(t)
	port := portOf(t, l)

	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, time.Second, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, "127.0.0.1", net.ParseIP("127.0.0.1"), []int{port, port + 1, port + 2, port + 3})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	cancel()

	// Channel must still close even after cancellation, without hanging
	// the test.
	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("results channel did not close after context cancellation")
	}
}

func TestScan_NilIP(t *testing.T) {
	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, time.Second, 1, nil)
	if _, err := scanner.Scan(context.Background(), "127.0.0.1", nil, []int{80}); err == nil {
		t.Error("expected error for nil IP")
	}
}

// TestScan_RefusedConnectionsReturnQuickly proves the "refuses
// connections" timeout scenario: a closed local port must be reported
// Open:false promptly, well under the configured DialTimeout, not by
// waiting out the full timeout.
func TestScan_RefusedConnectionsReturnQuickly(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := portOf(t, l)
	l.Close() // port is now closed; connections to it are refused

	const dialTimeout = 3 * time.Second
	scanner := NewTCPConnectScanner(&fakeValidator{allowed: true}, dialTimeout, 4, nil)

	start := time.Now()
	results, err := scanner.Scan(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), []int{closedPort})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for r := range results {
		if r.Open {
			t.Errorf("expected closed port to report Open:false, got Open:true")
		}
	}
	elapsed := time.Since(start)
	if elapsed > dialTimeout {
		t.Errorf("refused connection took %v to report, want well under the %v dial timeout (OS-level RST should be near-instant)", elapsed, dialTimeout)
	}
}
