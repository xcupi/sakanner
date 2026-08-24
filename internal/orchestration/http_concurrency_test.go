package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestRun_HTTPWorkersConcurrencyIsRespected empirically proves
// Concurrency.HTTPWorkers bounds the TRUE aggregate number of in-flight
// HTTP probes during probeAndFingerprint, mirroring
// internal/ports/concurrency_test.go's TestScan_TrueAggregateConcurrencyAcrossHosts
// for the HTTP stage Phase 2 relies on just as heavily (the crawler and
// JS-discovery stages share the same HTTPWorkers limit). Many open ports
// on one host, each held briefly by its handler, widen the window in
// which concurrent goroutines would pile up past the configured limit if
// it weren't actually enforced.
func TestRun_HTTPWorkersConcurrencyIsRespected(t *testing.T) {
	const (
		serverCount = 12
		httpWorkers = 3
		holdFor     = 80 * time.Millisecond
	)

	var inFlight, highWater int32
	handler := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			hw := atomic.LoadInt32(&highWater)
			if cur <= hw || atomic.CompareAndSwapInt32(&highWater, hw, cur) {
				break
			}
		}
		time.Sleep(holdFor)
		w.Write([]byte("ok"))
	})

	var ports []int
	var host string
	for i := 0; i < serverCount; i++ {
		srv := httptest.NewServer(handler)
		defer srv.Close()
		h, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("split host port: %v", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("parse port: %v", err)
		}
		host = h
		ports = append(ports, port)
	}

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.Concurrency.HTTPWorkers = httpWorkers
	p.Concurrency.PortWorkers = 32

	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: ports})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed", job.Status)
	}

	httpServices, err := p.Store.HTTPServices().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("HTTPServices().ListByScanJob: %v", err)
	}
	if len(httpServices) != serverCount {
		t.Fatalf("got %d http services, want %d -- test setup issue, not what's under test", len(httpServices), serverCount)
	}

	hw := atomic.LoadInt32(&highWater)
	if hw > httpWorkers {
		t.Errorf("observed %d concurrent in-flight HTTP probes, want <= %d (Concurrency.HTTPWorkers not enforced)", hw, httpWorkers)
	}
	if hw < 2 {
		t.Errorf("observed high-water mark = %d, suspiciously low -- probes may have run fully serially, which wouldn't actually exercise the concurrency limit", hw)
	}
}
