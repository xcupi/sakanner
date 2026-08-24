package orchestration

import (
	"context"
	"net"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/pkg/models"
)

// TestRun_DuplicateHostnameAcrossSourcesIsNotDuplicated is a regression
// test for a real bug found during Phase 2 acceptance testing: the same
// hostname discovered via two different sources in one job (an explicit
// target, and again via subdomain enumeration of its parent domain)
// previously persisted two separate Asset/Host pairs for the identical
// name, causing every downstream stage to scan it twice under two
// different Asset IDs. Fixed in discoverAndResolve/enumerateSubdomains
// via a whole-job seenHostnames set.
func TestRun_DuplicateHostnameAcrossSourcesIsNotDuplicated(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.Wordlist = []string{"www"}

	fr := p.Resolver.(*dns.FakeResolver)
	fr.Hosts["www.example.com"] = []net.IP{net.ParseIP("203.0.113.5")}

	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: "www.example.com", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create host target: %v", err)
	}
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t2", Value: "example.com", Type: models.TargetTypeDomain, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create domain target: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1", "t2"}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	assets, err := p.Store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Assets().ListByScanJob: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("assets = %+v, want exactly 1 (the same hostname discovered twice must not create two Assets)", assets)
	}
	if assets[0].Name != "www.example.com" || assets[0].Source != "target" {
		t.Errorf("asset = %+v, want Name=www.example.com Source=target (explicit target wins over the later duplicate discovery)", assets[0])
	}

	hosts, err := p.Store.Hosts().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Hosts().ListByScanJob: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want exactly 1", hosts)
	}
}

// TestRun_DuplicateHostnameNormalizationCaseAndTrailingDot proves the
// dedup check in TestRun_DuplicateHostnameAcrossSourcesIsNotDuplicated
// isn't just a literal string match -- "WWW.example.com." (mixed case,
// trailing FQDN dot) and "www.example.com" must be recognized as the
// same host.
func TestRun_DuplicateHostnameNormalizationCaseAndTrailingDot(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()

	fr := p.Resolver.(*dns.FakeResolver)
	fr.Hosts["www.example.com"] = []net.IP{net.ParseIP("203.0.113.5")}
	fr.Hosts["WWW.example.com."] = []net.IP{net.ParseIP("203.0.113.5")}

	ctx := context.Background()
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t1", Value: "www.example.com", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target 1: %v", err)
	}
	if err := p.Store.Targets().Create(ctx, models.Target{ID: "t2", Value: "WWW.example.com.", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target 2: %v", err)
	}
	if err := p.Store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: "www.example.com", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1", "t2"}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	assets, err := p.Store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Assets().ListByScanJob: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("assets = %+v, want exactly 1 (case/trailing-dot variants of the same host must dedup)", assets)
	}
}
