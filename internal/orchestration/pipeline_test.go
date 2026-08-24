package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func newTestPipeline(t *testing.T) (*Pipeline, func()) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}

	p := &Pipeline{
		Store:               store,
		Resolver:            dns.NewFakeResolver(),
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		Wordlist:            nil,
		DefaultPorts:        nil,
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 5 * time.Second, MaxRedirects: 3},
		Concurrency:         Concurrency{DNSWorkers: 2, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true, // tests dial 127.0.0.1, which is reserved by default
		MaxCIDRHosts:        256,
		EnumerateDNSRecords: true,
		Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
	}
	return p, func() { store.Close() }
}

func TestRun_FullPipeline_PersistsResults(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write([]byte("<html><head><title>Test Site</title></head></html>"))
	}))
	defer srv.Close()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
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
	target := models.Target{ID: "t1", Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job status=%s error=%s)", err, job.Status, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}
	if job.FinishedAt == nil {
		t.Error("job.FinishedAt is nil")
	}
	if len(job.ScopeSnapshot) != 1 {
		t.Errorf("job.ScopeSnapshot = %+v, want 1 rule snapshotted", job.ScopeSnapshot)
	}

	assets, err := p.Store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil || len(assets) != 1 {
		t.Fatalf("Assets: %v, len=%d", err, len(assets))
	}

	hosts, err := p.Store.Hosts().ListByScanJob(ctx, job.ID)
	if err != nil || len(hosts) != 1 || hosts[0].IPAddress != "127.0.0.1" {
		t.Fatalf("Hosts: %v, got %+v", err, hosts)
	}

	services, err := p.Store.Services().ListByScanJob(ctx, job.ID)
	if err != nil || len(services) != 1 || services[0].Port != port {
		t.Fatalf("Services: %v, got %+v, want port %d", err, services, port)
	}

	httpSvcs, err := p.Store.HTTPServices().ListByScanJob(ctx, job.ID)
	if err != nil || len(httpSvcs) != 1 {
		t.Fatalf("HTTPServices: %v, got %+v", err, httpSvcs)
	}
	if httpSvcs[0].StatusCode != 200 || httpSvcs[0].Title != "Test Site" {
		t.Errorf("HTTPService = %+v, want status 200 and title 'Test Site'", httpSvcs[0])
	}

	techs, err := p.Store.Technologies().ListByScanJob(ctx, job.ID)
	if err != nil || len(techs) != 1 || techs[0].Name != "nginx" {
		t.Fatalf("Technologies: %v, got %+v, want [nginx]", err, techs)
	}
	if techs[0].Version != "1.25.3" {
		t.Errorf("Technologies[0].Version = %q, want \"1.25.3\"", techs[0].Version)
	}
	if techs[0].Source != "fingerprint" {
		t.Errorf("Technologies[0].Source = %q, want \"fingerprint\"", techs[0].Source)
	}
}

func TestRun_ScopeDenialAbortsBeforeAnyStage(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	// No scope rules exist -> default deny.
	target := models.Target{ID: "t1", Value: "out-of-scope.example.com", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
	if err == nil {
		t.Fatal("expected Run to fail for an out-of-scope target")
	}
	if job.Status != models.ScanJobStatusFailed {
		t.Errorf("job.Status = %s, want failed", job.Status)
	}

	assets, err := p.Store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected zero assets when scope denial aborts before any stage runs, got %d", len(assets))
	}
}

func TestRun_ContextCancellation_ReturnsPromptly(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())

	target := models.Target{ID: "t1", Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(context.Background(), target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(context.Background(), rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	cancel() // cancelled before Run even starts

	done := make(chan struct{})
	go func() {
		p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{1, 2, 3}})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after context cancellation")
	}
}
