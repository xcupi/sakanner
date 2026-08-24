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
	"sakanner/pkg/models"
)

// These tests prove scope enforcement empirically through the full
// pipeline (not just at the internal/scope unit level): an allowed
// domain-suffix rule must let a subdomain reach real port/HTTP stages,
// while a rule that does not match must abort the job before any host is
// even resolved. All targets are local (httptest / loopback); nothing
// here ever touches a live external host.

func TestScopeEnforcement_DomainSuffixAllowsSubdomainThroughFullPipeline(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ip, port := serverIPPort(t, srv)

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: "sub.allowed.test", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.Targets().Create(ctx, target))

	rule := models.ScopeRule{ID: "r1", Value: "allowed.test", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.ScopeRules().Create(ctx, rule))

	p.Resolver.(*dns.FakeResolver).Hosts["sub.allowed.test"] = []net.IP{ip}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	services, err := p.Store.Services().ListByScanJob(ctx, job.ID)
	if err != nil || len(services) != 1 {
		t.Fatalf("expected the subdomain's port to be reached under the domain-suffix rule; Services: %v, %+v", err, services)
	}
}

func TestScopeEnforcement_UnrelatedDomainAbortsBeforeResolution(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: "totally-unrelated.test", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.Targets().Create(ctx, target))

	rule := models.ScopeRule{ID: "r1", Value: "allowed.test", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.ScopeRules().Create(ctx, rule))

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
	if err == nil {
		t.Fatal("expected an unrelated domain to be denied by an unrelated domain-suffix rule")
	}
	if job.Status != models.ScanJobStatusFailed {
		t.Errorf("job.Status = %s, want failed", job.Status)
	}
	hosts, _ := p.Store.Hosts().ListByScanJob(ctx, job.ID)
	if len(hosts) != 0 {
		t.Errorf("expected zero hosts (no DNS resolution should have occurred), got %d", len(hosts))
	}
}

func TestScopeEnforcement_DisallowedSiblingSubdomainDenied(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	// "evil-allowed.test" is NOT a subdomain of "allowed.test" -- it just
	// shares a substring. A naive strings.Contains/HasSuffix-without-dot
	// check would wrongly allow this; scope.Validator must not.
	target := models.Target{ID: "t1", Value: "evil-allowed.test", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.Targets().Create(ctx, target))

	rule := models.ScopeRule{ID: "r1", Value: "allowed.test", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.ScopeRules().Create(ctx, rule))

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
	if err == nil {
		t.Fatal("expected evil-allowed.test to be denied despite sharing a suffix substring with allowed.test")
	}
	if job.Status != models.ScanJobStatusFailed {
		t.Errorf("job.Status = %s, want failed", job.Status)
	}
}

func TestScopeEnforcement_CIDRTargetReachesPortScan(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, port := serverIPPort(t, srv)

	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: "127.0.0.1/30", Type: models.TargetTypeCIDR, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.Targets().Create(ctx, target))

	rule := models.ScopeRule{ID: "r1", Value: "127.0.0.1/30", Type: models.ScopeRuleCIDR, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.ScopeRules().Create(ctx, rule))

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{port}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	hosts, err := p.Store.Hosts().ListByScanJob(ctx, job.ID)
	if err != nil || len(hosts) == 0 {
		t.Fatalf("expected CIDR expansion to produce hosts; %v, %+v", err, hosts)
	}

	services, err := p.Store.Services().ListByScanJob(ctx, job.ID)
	if err != nil || len(services) != 1 {
		t.Fatalf("expected exactly one open service (127.0.0.1:%d); %v, %+v", port, err, services)
	}
}

func TestScopeEnforcement_CIDRTargetOutsideRuleDenied(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	ctx := context.Background()

	target := models.Target{ID: "t1", Value: "203.0.113.0/28", Type: models.TargetTypeCIDR, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.Targets().Create(ctx, target))

	// Rule authorizes a disjoint CIDR range.
	rule := models.ScopeRule{ID: "r1", Value: "198.51.100.0/28", Type: models.ScopeRuleCIDR, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	mustSeed(t, p.Store.ScopeRules().Create(ctx, rule))

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
	if err == nil {
		t.Fatal("expected CIDR target outside the authorized range to be denied")
	}
	if job.Status != models.ScanJobStatusFailed {
		t.Errorf("job.Status = %s, want failed", job.Status)
	}
}

func serverIPPort(t *testing.T, srv *httptest.Server) (net.IP, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("parse IP %q", host)
	}
	return ip, port
}

func mustSeed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}
