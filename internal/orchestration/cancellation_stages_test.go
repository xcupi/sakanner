package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"sakanner/pkg/models"
)

// TestRun_CancellationDuringPortScanStage cancels mid-way through port
// scanning specifically (as opposed to during discovery, covered
// elsewhere) and proves the scan stops promptly and reports Cancelled.
// A real rate limiter paces every dial attempt regardless of how fast
// the underlying connect() call completes, giving deterministic control
// over how long this stage takes.
func TestRun_CancellationDuringPortScanStage(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()

	p.MaxCIDRHosts = 64
	p.Concurrency.PortWorkers = 2
	p.PortLimiter = rate.NewLimiter(rate.Limit(50), 1) // ~50/sec pacing, burst 1

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "127.0.0.0/26", Type: models.TargetTypeCIDR, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.0/26", Type: models.ScopeRuleCIDR, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{1, 2, 3}})
	elapsed := time.Since(start)

	// 64 hosts * 3 ports = 192 dials, paced at ~50/sec would take
	// several seconds uncancelled; cancelling at 150ms must cut this off
	// well short of that.
	if elapsed > 2*time.Second {
		t.Errorf("Run took %v after cancellation at 150ms during port scanning, want well under 2s", elapsed)
	}
	if err == nil {
		t.Error("expected an error for a scan cancelled during port scanning")
	}
	if job.Status != models.ScanJobStatusCancelled {
		t.Errorf("job.Status = %s, want cancelled", job.Status)
	}
}

// TestRun_CancellationDuringHTTPProbeStage cancels mid-way through HTTP
// probing specifically, using a real slow HTTP server to force the
// stage to take measurable time.
func TestRun_CancellationDuringHTTPProbeStage(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case <-block:
		case <-time.After(3 * time.Second):
		}
		w.Write([]byte("ok"))
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

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
	p.HTTPConfig.Timeout = 10 * time.Second // longer than our cancellation window, so cancellation -- not the timeout -- is what ends the probe

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("Run took %v after cancellation at 300ms during HTTP probing (server would otherwise hold the request open for up to 3s), want well under 2s", elapsed)
	}
	if err == nil {
		t.Error("expected an error for a scan cancelled during HTTP probing")
	}
	if job.Status != models.ScanJobStatusCancelled {
		t.Errorf("job.Status = %s, want cancelled", job.Status)
	}
}
