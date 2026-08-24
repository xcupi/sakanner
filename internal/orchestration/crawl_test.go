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

func TestRun_CrawlDiscoversEndpoints(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<a href="/about">About</a>
			<form action="/login" method="post"></form>
			<script src="/app.js"></script>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>about page</body></html>`))
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

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 2
	p.CrawlMaxPages = 10

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	endpointsList, err := p.Store.Endpoints().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}

	byPath := map[string]models.Endpoint{}
	for _, e := range endpointsList {
		byPath[e.Path] = e
	}

	if e, ok := byPath["/"]; !ok || e.Source != "crawl" {
		t.Errorf("expected an endpoint for / with source=crawl, got %+v (all: %+v)", e, endpointsList)
	}
	if e, ok := byPath["/about"]; !ok || e.Source != "link" {
		t.Errorf("expected an endpoint for /about with source=link, got %+v", e)
	}
	if e, ok := byPath["/login"]; !ok || e.Source != "form" || e.Method != "POST" {
		t.Errorf("expected an endpoint for /login with source=form method=POST, got %+v", e)
	}
	if e, ok := byPath["/app.js"]; !ok || e.Source != "javascript" {
		t.Errorf("expected an endpoint for /app.js with source=javascript, got %+v", e)
	}
}

func TestRun_CrawlDisabledByDefault_NoEndpoints(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/about">About</a></body></html>`))
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
	// p.CrawlEnabled left at its zero value (false).

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	endpointsList, err := p.Store.Endpoints().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(endpointsList) != 0 {
		t.Errorf("got %d endpoints with CrawlEnabled=false, want 0", len(endpointsList))
	}
}
