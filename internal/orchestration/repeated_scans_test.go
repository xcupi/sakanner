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

// TestRun_RepeatedScansOfSameTarget scans the same target many times in
// a row and confirms each one succeeds independently and goroutine count
// stays flat -- proving no state leaks or accumulates across repeated
// runs of the same pipeline instance.
func TestRun_RepeatedScansOfSameTarget(t *testing.T) {
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

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	const iterations = 30
	jobIDs := map[string]bool{}
	for i := 0; i < iterations; i++ {
		job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
		if err != nil {
			t.Fatalf("iteration %d: Run: %v (job error: %s)", i, err, job.Error)
		}
		if job.Status != models.ScanJobStatusCompleted {
			t.Fatalf("iteration %d: status = %s, want completed", i, job.Status)
		}
		if jobIDs[job.ID] {
			t.Fatalf("iteration %d: duplicate job ID %s across repeated scans", i, job.ID)
		}
		jobIDs[job.ID] = true
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > baseline+5 {
		t.Errorf("goroutine count grew from %d to %d after %d repeated scans", baseline, after, iterations)
	}

	jobs, err := p.Store.ScanJobs().List(ctx)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != iterations {
		t.Errorf("got %d scan jobs, want %d (one per repeated scan, all independently recorded)", len(jobs), iterations)
	}
}

// TestRun_VeryLargePortRange proves scanning a large number of ports
// against a real target completes in bounded time and without excessive
// memory/goroutine growth, exercising the semaphore-bounded concurrency
// fix under real load rather than a small synthetic count.
func TestRun_VeryLargePortRange(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.Concurrency.PortWorkers = 50

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	ports := make([]int, 20000)
	for i := range ports {
		ports[i] = i + 1
	}

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	start := time.Now()
	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: ports})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("status = %s, want completed", job.Status)
	}
	if elapsed > 60*time.Second {
		t.Errorf("scanning 20,000 ports took %v, want well under 60s", elapsed)
	}
	t.Logf("scanned 20,000 ports in %v", elapsed)

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	afterGoroutines := runtime.NumGoroutine()
	if afterGoroutines > baselineGoroutines+10 {
		t.Errorf("goroutine count grew from %d to %d after a 20,000-port scan -- goroutines are not all cleaned up", baselineGoroutines, afterGoroutines)
	}
}
