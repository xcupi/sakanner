package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestRun_NoGoroutineLeak_WithCrawlingAndJSDiscovery extends the
// existing goroutine-leak coverage (goroutine_leak_test.go, which
// predates Phase 2 and never enables CrawlEnabled) to the crawler and
// JavaScript-discovery stages Phase 2 added -- both spawn their own
// errgroup-bounded goroutines and issue their own HTTP fetches
// independent of the base probe/fingerprint stage's.
func TestRun_NoGoroutineLeak_WithCrawlingAndJSDiscovery(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 20

	ctx := context.Background()
	baseline := stableGoroutineCount(t)

	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>
			<script src="/app.js"></script>
		</body></html>`))
	})
	for _, path := range []string{"/a", "/b", "/c"} {
		mux.HandleFunc(path, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.Write([]byte("page")) })
	}
	mux.HandleFunc("/app.js", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("/*! jQuery JavaScript Library v3.6.0 */"))
	})
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

	for i := 0; i < 5; i++ {
		target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
		if err := p.Store.Targets().Create(ctx, target); err != nil {
			t.Fatalf("create target: %v", err)
		}
		rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
		if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
			t.Fatalf("create scope rule: %v", err)
		}
		job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
		if err != nil || job.Status != models.ScanJobStatusCompleted {
			t.Fatalf("scan %d: err=%v status=%s (error: %s)", i, err, job.Status, job.Error)
		}
		if err := p.Store.Targets().Delete(ctx, "t1"); err != nil {
			t.Fatalf("delete target for reuse: %v", err)
		}
		if err := p.Store.ScopeRules().Delete(ctx, "r1"); err != nil {
			t.Fatalf("delete scope rule for reuse: %v", err)
		}
	}

	after := stableGoroutineCount(t)
	if after > baseline+2 {
		t.Errorf("goroutine count grew from %d to %d after 5 crawl+JS-discovery scans -- possible leak in the crawler or JS-discovery stage", baseline, after)
	}
}
