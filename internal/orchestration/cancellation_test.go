package orchestration

import (
	"context"
	"net"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/pkg/models"
)

// slowResolver wraps a Resolver with an artificial per-call delay that
// still respects ctx cancellation, giving deterministic control over how
// long a scan takes so a mid-scan cancellation test isn't racing against
// unpredictably-fast real I/O.
type slowResolver struct {
	inner dns.Resolver
	delay time.Duration
}

func (s *slowResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.inner.LookupHost(ctx, host)
}
func (s *slowResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return s.inner.LookupCNAME(ctx, host)
}
func (s *slowResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return s.inner.LookupMX(ctx, host)
}
func (s *slowResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return s.inner.LookupTXT(ctx, host)
}
func (s *slowResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return s.inner.LookupNS(ctx, host)
}

func TestRun_MidScanCancellation_GracefulShutdown(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()

	fake := dns.NewFakeResolver()
	wordlist := make([]string, 30)
	for i := range wordlist {
		wordlist[i] = "w" + string(rune('a'+i))
		fake.Hosts[wordlist[i]+".slow.test"] = []net.IP{net.ParseIP("203.0.113.1")}
	}
	p.Resolver = &slowResolver{inner: fake, delay: 80 * time.Millisecond}
	p.Wordlist = wordlist
	p.Concurrency.DNSWorkers = 2 // low concurrency so 30 words * 80ms / 2 ~= 1.2s uncancelled

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "slow.test", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "slow.test", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(150 * time.Millisecond) // let a handful of resolutions complete, then cut it short
		cancel()
	}()

	start := time.Now()
	job, err := p.Run(runCtx, RunOptions{TargetIDs: []string{"t1"}})
	elapsed := time.Since(start)

	// Graceful shutdown: Run must return well before the ~1.2s
	// uncancelled runtime, proving cancellation actually stopped work
	// rather than running to completion.
	if elapsed > 800*time.Millisecond {
		t.Errorf("Run took %v after cancellation at ~150ms, want well under the ~1.2s uncancelled runtime (cancellation did not stop work promptly)", elapsed)
	}
	if err == nil {
		t.Error("expected Run to return an error for a cancelled scan")
	}

	// Scan status must reflect cancellation, not a generic failure or a
	// job stuck at "running".
	if job.Status != models.ScanJobStatusCancelled {
		t.Errorf("job.Status = %s, want %s", job.Status, models.ScanJobStatusCancelled)
	}
	if job.FinishedAt == nil {
		t.Error("job.FinishedAt is nil after cancellation -- terminal state was not recorded")
	}

	// No corrupted database state: the store must still be fully usable
	// afterward (no dangling lock, no broken connection), and the job's
	// terminal status must actually be the one on record, not "running".
	if err := p.Store.Ping(context.Background()); err != nil {
		t.Errorf("store is not usable after a cancelled scan: %v", err)
	}
	stored, err := p.Store.ScanJobs().Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Get after cancellation: %v", err)
	}
	if stored.Status != models.ScanJobStatusCancelled {
		t.Errorf("persisted job.Status = %s, want %s (a stuck 'running' row would mean the final write was lost)", stored.Status, models.ScanJobStatusCancelled)
	}

	// A fresh, uncancelled scan must still work afterward -- proves no
	// resource (DB connection, goroutine holding a lock) was left in a
	// bad state by the cancelled run.
	target2 := models.Target{ID: "t2", Value: "203.0.113.9", Type: models.TargetTypeIP, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(context.Background(), target2); err != nil {
		t.Fatalf("create second target: %v", err)
	}
	rule2 := models.ScopeRule{ID: "r2", Value: "203.0.113.9", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(context.Background(), rule2); err != nil {
		t.Fatalf("create second scope rule: %v", err)
	}
	p.Resolver = dns.NewFakeResolver() // restore a normal resolver for the follow-up run
	job2, err := p.Run(context.Background(), RunOptions{TargetIDs: []string{"t2"}, Ports: []int{1}})
	if err != nil {
		t.Fatalf("follow-up Run after cancellation: %v (job error: %s)", err, job2.Error)
	}
	if job2.Status != models.ScanJobStatusCompleted {
		t.Errorf("follow-up job.Status = %s, want completed", job2.Status)
	}
}
