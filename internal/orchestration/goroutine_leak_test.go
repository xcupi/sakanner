package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// stableGoroutineCount lets the runtime settle (finalizers, GC-triggered
// goroutine exits, deferred cleanup) before sampling, to avoid a flaky
// off-by-a-few-during-teardown reading.
func stableGoroutineCount(t *testing.T) int {
	t.Helper()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	return runtime.NumGoroutine()
}

// TestRun_NoGoroutineLeak_AcrossOutcomes runs several scans to
// completion, denial, and cancellation, and confirms the goroutine count
// returns to baseline afterward -- proving none of these code paths
// leaks a goroutine blocked forever on a channel send, a semaphore
// acquire, or a context that's never cancelled.
func TestRun_NoGoroutineLeak_AcrossOutcomes(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	baseline := stableGoroutineCount(t)

	// 1. A normal, successful scan.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}
	if job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}}); err != nil || job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("successful scan setup failed: err=%v status=%s", err, job.Status)
	}

	// 2. A scope-denied scan (aborts before any stage runs).
	target2 := models.Target{ID: "t2", Value: "denied.test", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target2); err != nil {
		t.Fatalf("create target2: %v", err)
	}
	if _, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t2"}}); err == nil {
		t.Fatal("expected scope denial")
	}

	// 3. A cancelled scan.
	target3 := models.Target{ID: "t3", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target3); err != nil {
		t.Fatalf("create target3: %v", err)
	}
	rule3 := models.ScopeRule{ID: "r3", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule3); err != nil {
		t.Fatalf("create rule3: %v", err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	p.Run(cancelCtx, RunOptions{TargetIDs: []string{"t3"}, Ports: []int{port}})

	after := stableGoroutineCount(t)
	// Allow a small amount of slack for runtime/test-framework
	// housekeeping goroutines that aren't under our control, but a real
	// leak (one goroutine per port/host that never exits) would show up
	// as a count that grows with each scan, not a small constant.
	if after > baseline+5 {
		t.Errorf("goroutine count grew from %d to %d after 3 scans (completed/denied/cancelled) -- possible goroutine leak", baseline, after)
	}
	t.Logf("goroutine count: baseline=%d after=%d", baseline, after)
}

// TestRun_NoGoroutineLeak_RepeatedCancellation runs many cancelled scans
// in a row and confirms goroutine count stays flat rather than growing
// linearly with each one, which would indicate every cancelled scan
// leaks a fixed number of goroutines.
func TestRun_NoGoroutineLeak_RepeatedCancellation(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	baseline := stableGoroutineCount(t)

	const iterations = 20
	for i := 0; i < iterations; i++ {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		p.Run(cancelCtx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{1, 2, 3, 4, 5}})
	}

	after := stableGoroutineCount(t)
	if after > baseline+5 {
		t.Errorf("goroutine count grew from %d to %d after %d cancelled scans -- goroutine leak scales with scan count", baseline, after, iterations)
	}
	t.Logf("goroutine count after %d cancelled scans: baseline=%d after=%d", iterations, baseline, after)
}
