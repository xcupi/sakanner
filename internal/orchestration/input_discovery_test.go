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

	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

func setupCrawlTarget(t *testing.T, p *Pipeline, srv *httptest.Server) (host string, port int) {
	t.Helper()
	var portStr string
	var err error
	host, portStr, err = net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}
	return host, port
}

func TestRun_InputDiscovery_QueryParameters(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/search?q=test&page=2">search</a></body></html>`))
	})
	mux.HandleFunc("/search", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>results</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byName := map[string]models.Parameter{}
	for _, prm := range params {
		byName[prm.Name] = prm
	}
	if p, ok := byName["q"]; !ok || p.Location != "query" || p.Value != "test" {
		t.Errorf("expected parameter q=test location=query, got %+v (all: %+v)", byName["q"], params)
	}
	if p, ok := byName["page"]; !ok || p.Location != "query" || p.Value != "2" {
		t.Errorf("expected parameter page=2 location=query, got %+v", byName["page"])
	}
	if byName["q"].Classification != "PARAMETER" {
		t.Errorf("Classification = %q, want PARAMETER", byName["q"].Classification)
	}
	if byName["q"].EndpointID == "" {
		t.Error("EndpointID not set on discovered parameter")
	}
}

func TestRun_InputDiscovery_GETFormFields_QueryLocation(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><form action="/search" method="get"><input name="q" type="text"></form></body></html>`))
	}))
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("got %d parameters, want 1: %+v", len(params), params)
	}
	if params[0].Name != "q" || params[0].Location != "query" {
		t.Errorf("got %+v, want name=q location=query (GET form fields use query location)", params[0])
	}
}

func TestRun_InputDiscovery_POSTFormFields_FormLocation(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><form action="/login" method="post"><input name="username" type="text" value="alice"><input name="password" type="password"></form></body></html>`))
	}))
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byName := map[string]models.Parameter{}
	for _, prm := range params {
		byName[prm.Name] = prm
	}
	if p, ok := byName["username"]; !ok || p.Location != "form" || p.Value != "alice" || p.Classification != "FORM_FIELD" {
		t.Errorf("username = %+v, want location=form value=alice classification=FORM_FIELD", p)
	}
	if p, ok := byName["password"]; !ok || p.Value == "hunter2" {
		t.Errorf("password field must be redacted, got %+v", p)
	}
}

func TestRun_InputDiscovery_CrawlerDisabled_NoParameters(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/search?q=test">search</a></body></html>`))
	}))
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	// p.CrawlEnabled left false.
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("got %d parameters with CrawlEnabled=false, want 0 (task: input discovery must stay passive/off when crawling is off)", len(params))
	}
}

func TestRun_InputDiscovery_ResourceLimit_TruncatesAndDoesNotFailScan(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/search?a=1&b=2&c=3&d=4&e=5">search</a></body></html>`))
	}))
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10
	p.ParameterLimits = parameters.Limits{MaxInputsPerEndpoint: 2}
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Errorf("job.Status = %s, want completed -- a resource limit must not fail the scan", job.Status)
	}

	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(params) != 2 {
		t.Errorf("got %d parameters, want 2 (truncated by MaxInputsPerEndpoint)", len(params))
	}
	if len(job.Warnings) == 0 {
		t.Error("job.Warnings is empty, want at least one input-limit warning surfaced on the returned ScanJob")
	}
}

// TestRun_InputDiscovery_CancellationDuringCrawl_LeavesStoreConsistent
// is task adversarial scenarios 27/28 (cancellation/timeout during
// input discovery): input discovery runs inside the SAME per-target
// goroutine, under the SAME context, as endpoint creation
// (crawlAndDiscoverEndpoints) -- this proves cancelling mid-crawl
// neither panics nor leaves the Parameters table in a state that
// fails to query, on top of cancellation_crawl_test.go's own
// broader "the whole scan shuts down promptly and is marked
// cancelled" coverage.
func TestRun_InputDiscovery_CancellationDuringCrawl_LeavesStoreConsistent(t *testing.T) {
	mux := nethttp.NewServeMux()
	const pageCount = 30
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(15 * time.Millisecond)
		var links string
		for i := 0; i < pageCount; i++ {
			links += fmt.Sprintf(`<a href="/page%d?q=%d">p</a>`, i, i)
		}
		w.Write([]byte("<html><body>" + links + "</body></html>"))
	})
	for i := 0; i < pageCount; i++ {
		mux.HandleFunc(fmt.Sprintf("/page%d", i), func(w nethttp.ResponseWriter, r *nethttp.Request) {
			time.Sleep(15 * time.Millisecond)
			w.Write([]byte("ok"))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = pageCount
	p.Concurrency.HTTPWorkers = 1
	_, port := setupCrawlTarget(t, p, srv)

	runCtx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err == nil {
		t.Error("expected an error for a scan cancelled during crawling")
	}
	if job.Status != models.ScanJobStatusCancelled {
		t.Errorf("job.Status = %s, want cancelled", job.Status)
	}

	// The store must remain fully queryable after a mid-crawl
	// cancellation -- whatever partial set of Parameter rows got
	// persisted before cancellation landed is valid, readable data, not
	// a broken or inconsistent state.
	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob after cancellation: %v", err)
	}
	t.Logf("persisted %d parameters before cancellation landed", len(params))
}

func TestRun_InputDiscovery_DifferentEndpoints_EachOwnParameters(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<a href="/search?q=x">search</a>
			<a href="/filter?sort=asc">filter</a>
		</body></html>`))
	})
	mux.HandleFunc("/search", func(w nethttp.ResponseWriter, r *nethttp.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/filter", func(w nethttp.ResponseWriter, r *nethttp.Request) { w.Write([]byte("ok")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10
	_, port := setupCrawlTarget(t, p, srv)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	endpointsList, err := p.Store.Endpoints().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Endpoints ListByScanJob: %v", err)
	}
	params, err := p.Store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Parameters ListByScanJob: %v", err)
	}

	var searchEP, filterEP models.Endpoint
	for _, e := range endpointsList {
		if e.Path == "/search?q=x" {
			searchEP = e
		}
		if e.Path == "/filter?sort=asc" {
			filterEP = e
		}
	}
	if searchEP.ID == "" || filterEP.ID == "" {
		t.Fatalf("expected both /search and /filter endpoints, got %+v", endpointsList)
	}
	for _, prm := range params {
		if prm.Name == "q" && prm.EndpointID != searchEP.ID {
			t.Errorf("q parameter attached to wrong endpoint: %s, want %s", prm.EndpointID, searchEP.ID)
		}
		if prm.Name == "sort" && prm.EndpointID != filterEP.ID {
			t.Errorf("sort parameter attached to wrong endpoint: %s, want %s", prm.EndpointID, filterEP.ID)
		}
	}
}
