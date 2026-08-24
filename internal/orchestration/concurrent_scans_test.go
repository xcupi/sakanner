package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"sakanner/pkg/models"

	"github.com/google/uuid"
)

// TestRun_ConcurrentScansOnSameStore proves multiple scans running
// concurrently in the same process against the same Store don't
// deadlock and don't corrupt each other's data, even when they target
// the same underlying service.
func TestRun_ConcurrentScansOnSameStore(t *testing.T) {
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

	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	const concurrentScans = 10
	targetIDs := make([]string, concurrentScans)
	for i := range targetIDs {
		id := uuid.NewString()
		targetIDs[i] = id
		target := models.Target{ID: id, Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
		if err := p.Store.Targets().Create(ctx, target); err != nil {
			t.Fatalf("create target %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, concurrentScans)
	statuses := make([]models.ScanJobStatus, concurrentScans)
	for i := 0; i < concurrentScans; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := p.Run(ctx, RunOptions{TargetIDs: []string{targetIDs[i]}, Ports: []int{port}})
			errs[i] = err
			statuses[i] = job.Status
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent scans deadlocked -- did not complete within 20s")
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("scan %d: err=%v status=%s", i, err, statuses[i])
		}
		if statuses[i] != models.ScanJobStatusCompleted {
			t.Errorf("scan %d: status=%s, want completed", i, statuses[i])
		}
	}

	// Every scan must have produced its own distinct job with its own
	// distinct results -- no cross-contamination between concurrent
	// jobs sharing the same Store.
	jobs, err := p.Store.ScanJobs().List(ctx)
	if err != nil {
		t.Fatalf("list scan jobs: %v", err)
	}
	if len(jobs) != concurrentScans {
		t.Fatalf("got %d scan jobs, want %d", len(jobs), concurrentScans)
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		if seen[j.ID] {
			t.Errorf("duplicate scan job ID %s -- job ID collision under concurrency", j.ID)
		}
		seen[j.ID] = true

		services, err := p.Store.Services().ListByScanJob(ctx, j.ID)
		if err != nil {
			t.Fatalf("list services for job %s: %v", j.ID, err)
		}
		if len(services) != 1 {
			t.Errorf("job %s: got %d services, want exactly 1 (no cross-job contamination)", j.ID, len(services))
		}
	}
}

// TestRun_DuplicateTargetValue proves adding the same target value twice
// (as two separate Target rows, since sakanner doesn't enforce value
// uniqueness) and scanning both doesn't corrupt state or double-count
// incorrectly -- it should simply produce two independent, correct scan
// jobs.
func TestRun_DuplicateTargetValue(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	id1, id2 := uuid.NewString(), uuid.NewString()
	for _, id := range []string{id1, id2} {
		target := models.Target{ID: id, Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
		if err := p.Store.Targets().Create(ctx, target); err != nil {
			t.Fatalf("create target %s: %v", id, err)
		}
	}

	targets, err := p.Store.Targets().List(ctx)
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (duplicate values are distinct rows)", len(targets))
	}

	job1, err := p.Run(ctx, RunOptions{TargetIDs: []string{id1}, Ports: []int{1}})
	if err != nil {
		t.Fatalf("Run 1: %v (error: %s)", err, job1.Error)
	}
	job2, err := p.Run(ctx, RunOptions{TargetIDs: []string{id2}, Ports: []int{1}})
	if err != nil {
		t.Fatalf("Run 2: %v (error: %s)", err, job2.Error)
	}

	if job1.ID == job2.ID {
		t.Fatal("duplicate-target scans produced the same job ID")
	}
	if job1.Status != models.ScanJobStatusCompleted || job2.Status != models.ScanJobStatusCompleted {
		t.Errorf("job1.Status=%s job2.Status=%s, want both completed", job1.Status, job2.Status)
	}
}
