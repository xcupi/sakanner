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

func TestRun_JavaScriptDiscoveryFingerprintsSameOriginScript(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><script src="/static/app.js"></script></body></html>`))
	})
	mux.HandleFunc("/static/app.js", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`/*! jQuery JavaScript Library v3.6.0 | (c) OpenJS Foundation */`))
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
	p.CrawlMaxDepth = 1
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

	techs, err := p.Store.Technologies().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}

	var found *models.Technology
	for i := range techs {
		if techs[i].Name == "jQuery" {
			found = &techs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a jQuery Technology discovered from the fetched script, got %+v", techs)
	}
	if found.Version != "3.6.0" {
		t.Errorf("jQuery Version = %q, want 3.6.0", found.Version)
	}
	if found.Category != "javascript-library" {
		t.Errorf("jQuery Category = %q, want javascript-library", found.Category)
	}
}

func TestRun_JavaScriptDiscoverySkipsCrossOriginScripts(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><script src="https://cdn.example.invalid/lib.js"></script></body></html>`))
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
	p.CrawlEnabled = true
	p.CrawlMaxDepth = 1
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

	// The fake resolver has no entry for cdn.example.invalid, so if the
	// pipeline ever attempted to dial it (rather than skipping it as
	// cross-origin before fetching), the run would surface that failure.
	// A clean completion here is what proves the skip actually happened.
	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	techs, err := p.Store.Technologies().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, tech := range techs {
		if tech.Name != "" && tech.Category == "javascript-library" {
			t.Errorf("expected no javascript-library technology from an unfetched cross-origin script, got %+v", tech)
		}
	}
}
