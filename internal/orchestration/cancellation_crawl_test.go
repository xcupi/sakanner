package orchestration

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestRun_CancellationDuringCrawlStage cancels mid-way through crawling
// specifically -- a Phase 2 addition not covered by
// cancellation_stages_test.go's port-scan/HTTP-probe-stage tests
// (written before Phase 2 existed). A crawlable site with many pages,
// each responding slowly enough to make the crawl take measurable time,
// forces cancellation to land mid-crawl rather than after it's already
// finished.
func TestRun_CancellationDuringCrawlStage(t *testing.T) {
	mux := nethttp.NewServeMux()
	const pageCount = 50
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(20 * time.Millisecond)
		var links string
		for i := 0; i < pageCount; i++ {
			links += fmt.Sprintf(`<a href="/page%d">p</a>`, i)
		}
		w.Write([]byte("<html><body>" + links + "</body></html>"))
	})
	for i := 0; i < pageCount; i++ {
		mux.HandleFunc(fmt.Sprintf("/page%d", i), func(w nethttp.ResponseWriter, r *nethttp.Request) {
			time.Sleep(20 * time.Millisecond)
			w.Write([]byte("page"))
		})
	}
	srv := httptest.NewServer(mux)
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
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = pageCount
	p.Concurrency.HTTPWorkers = 1 // force pages to be fetched close to serially, widening the cancellation window

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
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	elapsed := time.Since(start)

	// Uncancelled, ~50 pages at ~20ms each with HTTPWorkers=1 would take
	// roughly 1s; cancelling at 200ms must cut this off well short.
	if elapsed > 3*time.Second {
		t.Errorf("Run took %v after cancellation at 200ms during crawling, want well under 3s", elapsed)
	}
	if err == nil {
		t.Error("expected an error for a scan cancelled during crawling")
	}
	if job.Status != models.ScanJobStatusCancelled {
		t.Errorf("job.Status = %s, want cancelled", job.Status)
	}

	// The job's terminal status must itself still be correctly
	// persisted despite the cancellation -- not left stuck at "running".
	stored, getErr := p.Store.ScanJobs().Get(ctx, job.ID)
	if getErr != nil {
		t.Fatalf("retrieve job after cancellation: %v", getErr)
	}
	if stored.Status != models.ScanJobStatusCancelled {
		t.Errorf("persisted job.Status = %s, want cancelled", stored.Status)
	}
}
