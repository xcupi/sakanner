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

// These tests prove the pipeline handles a misbehaving external tool
// gracefully at the job level, not just at the adapter's own unit-test
// level (see internal/{discovery,dns,ports,http,crawler}'s own
// *_test.go files, which already cover each adapter's tool-installed/
// tool-missing/valid-output cases individually via the same
// testutil.WriteScript fake-binary pattern). naabu is used as the
// representative dial-performing tool and subfinder as the
// representative name-only tool -- every integration goes through the
// same pkg/plugins.RunJSONLines, so these two cover the shared failure
// surface without duplicating five near-identical test files.

func labTarget(t *testing.T, p *Pipeline, host string) string {
	t.Helper()
	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: host, Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}
	return "t1"
}

// D. Malformed output: valid JSON lines mixed with garbage/banner text
// must not crash or abort the scan -- pkg/plugins.RunJSONLines already
// skips unparseable lines; this proves the pipeline built on top of it
// behaves the same way.
func TestRun_NaabuMalformedOutputDoesNotFailScan(t *testing.T) {
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

	binary := testutil.WriteScript(t, "naabu", `
echo 'this is not json'
echo '{"ip":"`+host+`","port":`+portStr+`}'
echo '{malformed'
exit 0
`)
	t.Setenv("PATH", filepath.Dir(binary))

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.PortsBackend = "naabu"
	tid := labTarget(t, p, host)

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{tid}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed despite malformed tool output", job.Status)
	}
	services, err := p.Store.Services().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(services) != 1 || services[0].Port != port {
		t.Fatalf("services = %+v, want exactly the one valid line's port %d despite surrounding garbage", services, port)
	}
}

// F. Non-zero exit: naabu exiting non-zero must not fail the whole scan
// job -- ports.naabuScanner logs and yields no results for that host,
// same as "the tool legitimately found nothing."
func TestRun_NaabuNonZeroExitDoesNotFailScan(t *testing.T) {
	binary := testutil.WriteScript(t, "naabu", `
echo 'permission denied: raw sockets require CAP_NET_RAW' >&2
exit 1
`)
	t.Setenv("PATH", filepath.Dir(binary))

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.PortsBackend = "naabu"
	tid := labTarget(t, p, "127.0.0.1")

	job, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{tid}, Ports: []int{65500}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed despite the tool exiting non-zero", job.Status)
	}
	services, err := p.Store.Services().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("services = %+v, want none (the tool failed, not found anything)", services)
	}
}

// E. Tool times out (hangs): a subprocess that never exits must not hang
// the whole scan past the run's own context deadline.
func TestRun_SubfinderHangDoesNotHangScan(t *testing.T) {
	// A pure shell-builtin busy loop, not "sleep 30": t.Setenv below
	// REPLACES PATH with just this script's directory, so an external
	// command like sleep would fail to resolve at all (exit 127) rather
	// than actually hang -- ":" is a POSIX shell builtin, guaranteed to
	// need no PATH lookup, so this genuinely never exits on its own.
	binary := testutil.WriteScript(t, "subfinder", `
while :; do :; done
`)
	t.Setenv("PATH", filepath.Dir(binary))

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.DiscoveryBackend = "subfinder"
	tid := labTarget(t, p, "example.com")
	// example.com must be a domain target (not IP) to trigger subdomain
	// enumeration at all; scope must cover it.
	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t2", Value: "example.com", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create domain target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r2", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	start := time.Now()
	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{tid, "t2"}})
	elapsed := time.Since(start)

	// A lower bound, not just an upper one: this is what catches the
	// scenario where the subprocess isn't actually hanging at all (e.g.
	// it failed to start and exited immediately) -- a genuine hang must
	// run into something close to the 3s deadline before Run returns,
	// not return in a few milliseconds by coincidence.
	if elapsed < 2*time.Second {
		t.Fatalf("Run returned after only %v -- the subprocess did not actually hang until the context deadline as this test requires", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("Run took %v after a 3s context deadline against a hanging subprocess, want well under 10s", elapsed)
	}
	// A hung subprocess forcing ctx to expire is expected to surface as
	// a cancelled/failed job, not a panic or an indefinite hang -- either
	// outcome is acceptable here, promptness is what's being verified.
	_ = err
	if job.Status == models.ScanJobStatusRunning || job.Status == "" {
		t.Errorf("job.Status = %q, want a terminal status even though subfinder hung", job.Status)
	}
}
