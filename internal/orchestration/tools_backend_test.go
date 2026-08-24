package orchestration

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"sakanner/internal/testutil"
	"sakanner/pkg/models"
)

// TestRun_NaabuBackendDiscoversPorts is an end-to-end check that a
// pluggable stage's external-tool path is wired all the way through
// Pipeline.Run: PortsBackend="naabu" with a fake naabu binary on PATH
// should produce the same persisted Service a native port scan would.
func TestRun_NaabuBackendDiscoversPorts(t *testing.T) {
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

	binary := testutil.WriteScript(t, "naabu", `echo '{"ip":"`+host+`","port":`+portStr+`}'`+"\n")
	t.Setenv("PATH", filepath.Dir(binary))

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.PortsBackend = "naabu"

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

	services, err := p.Store.Services().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(services) != 1 || services[0].Port != port {
		t.Fatalf("services = %+v, want exactly one service on port %d", services, port)
	}
}

// TestRun_InvalidBackendFailsJobBeforeRunning proves a misconfigured
// backend string is surfaced as a failed job (not a panic or a silent
// fallback), and is caught before the job is even marked "running".
func TestRun_InvalidBackendFailsJobBeforeRunning(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.PortsBackend = "nmap" // not a recognized backend for this stage

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "127.0.0.1", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
	if err == nil {
		t.Fatal("expected an error for an invalid ports backend")
	}
	if job.Status != models.ScanJobStatusFailed {
		t.Errorf("job.Status = %s, want failed", job.Status)
	}
}
