// Package orchestration wires sakanner's Phase 1 pipeline stages
// together: scope validation, asset discovery, DNS resolution, port
// scanning, HTTP probing, and technology fingerprinting.
//
// The scope.Validator used for an entire scan job is built once, from
// the ScopeRules on record at the moment Run is called, and that same
// snapshot is stored on the ScanJob and reused for the whole run -- a
// rule edited in another terminal mid-scan does not affect a scan
// already in progress, and every dial made during the run traces back to
// exactly the rule set recorded on its job.
package orchestration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	nethttp "net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"sakanner/internal/auth"
	"sakanner/internal/crawler"
	"sakanner/internal/discovery"
	"sakanner/internal/dns"
	"sakanner/internal/endpoints"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/parameters"
	"sakanner/internal/ports"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// Concurrency bounds parallel work per pipeline stage.
type Concurrency struct {
	DNSWorkers  int
	PortWorkers int
	HTTPWorkers int
}

// Pipeline holds the dependencies needed to run a scan job. Per-run,
// scope-bound components (the Validator, the port Scanner, the HTTP
// Prober) are constructed fresh inside Run from the current ScopeRules,
// not held here, so each run gets its own snapshot.
type Pipeline struct {
	Store         storage.Store
	Resolver      dns.Resolver
	Fingerprinter fingerprint.Fingerprinter

	Wordlist            []string
	DefaultPorts        []int
	PortDialTimeout     time.Duration
	HTTPConfig          httpstage.Config
	PortLimiter         *rate.Limiter
	HTTPLimiter         *rate.Limiter
	Concurrency         Concurrency
	AllowReservedRanges bool
	MaxCIDRHosts        int
	EnumerateDNSRecords bool

	// Crawling is comparatively invasive/slow (many extra requests per
	// service), so it's config-gated and defaults to a modest footprint
	// rather than being unconditionally on.
	CrawlEnabled  bool
	CrawlMaxDepth int
	CrawlMaxPages int

	// ParameterLimits bounds Phase 3.13 input discovery -- gated by the
	// SAME CrawlEnabled flag above (task's "PROFILE INTERACTION: input
	// discovery should remain disabled unless the existing recon
	// implementation already performs passive input extraction... do
	// not introduce active behavior" -- since discovery only ever reads
	// already-crawled pages, "crawling is on" already implies "passive
	// extraction from that crawl is on," with no separate toggle
	// needed). A zero-value Limits{} is normalized to
	// parameters.DefaultLimits() at use, never treated as unbounded.
	ParameterLimits parameters.Limits

	// AuthSession, if non-nil, is an already-authenticated Phase 3.14
	// session (resolved and authenticated by the caller, e.g.
	// cmd/scanner, BEFORE Run is ever called -- see
	// docs/phase-3-14-authentication.md "Where authentication happens").
	// crawlAndDiscoverEndpoints derives host-pinned cookies/headers from
	// it (Session.CookiesFor/HeadersFor) for each crawl target -- the
	// ONLY place this Pipeline currently uses a session; the initial
	// port/HTTP-probe/fingerprint stage remains unauthenticated by
	// design (a deliberate, documented scope boundary for this phase,
	// not an oversight). nil (every pre-Phase-3.14 caller) preserves
	// crawling's exact prior behavior: no cookies or headers attached.
	AuthSession *auth.Session

	// Backends select which pluggable implementation each stage uses:
	// "" or "native" (built-in), "auto" (use the matching external tool
	// if found on PATH, else native), or the tool's own name to require
	// it explicitly. See pkg/plugins.Resolve for the shared contract.
	DiscoveryBackend string // subfinder
	DNSBackend       string // dnsx
	PortsBackend     string // naabu
	HTTPBackend      string // httpx
	CrawlBackend     string // katana

	Logger *slog.Logger
}

// RunOptions configures one pipeline execution.
type RunOptions struct {
	TargetIDs []string
	Ports     []int // overrides p.DefaultPorts if non-empty

	// ScanJobID, if non-empty, is used as the new ScanJob's ID instead
	// of a freshly generated one -- so a caller that runs further
	// stages after Run returns (detection, correlation, risk, evidence
	// -- see internal/orchestrator, Phase 3.11) can propagate ONE scan
	// ID across every stage instead of Run silently minting its own.
	// Empty (the zero value, and every pre-Phase-3.11 caller) preserves
	// the original behavior exactly: Run generates a fresh UUID.
	ScanJobID string
}

// Run executes the Phase 1 pipeline end-to-end for the given targets,
// persisting each stage's output as it's produced, and honors ctx
// cancellation. It always returns the terminal ScanJob (completed,
// failed, or cancelled) alongside any error.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) (models.ScanJob, error) {
	scanJobID := opts.ScanJobID
	if scanJobID == "" {
		scanJobID = uuid.NewString()
	}
	now := time.Now().UTC()
	job := models.ScanJob{
		ID:        scanJobID,
		TargetIDs: opts.TargetIDs,
		Status:    models.ScanJobStatusPending,
		StartedAt: now,
		CreatedAt: now,
	}
	logger := logging.WithScanJob(p.Logger, job.ID)

	targets, err := p.loadTargets(ctx, opts.TargetIDs)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: loading targets: %w", err))
	}

	rules, err := p.Store.ScopeRules().List(ctx)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: loading scope rules: %w", err))
	}
	job.ScopeSnapshot = rules
	validator := scope.NewValidator(rules, p.AllowReservedRanges)

	// Validate every literal target against scope before anything else
	// runs -- a single out-of-scope target aborts the whole job rather
	// than silently skipping it.
	for _, t := range targets {
		decision, err := validator.CheckHost(ctx, t.Value)
		if err != nil {
			return p.fail(ctx, job, fmt.Errorf("orchestration: scope check for target %q: %w", t.Value, err))
		}
		if !decision.Allowed {
			return p.fail(ctx, job, fmt.Errorf("orchestration: target %q is out of scope: %s", t.Value, decision.Reason))
		}
	}

	// Each pluggable stage picks its backend (native, or a matching
	// external tool) here, using the per-run logger so a WARN about a
	// sensitive external tool being selected is correlated with this
	// job's ID. A bad backend string is a configuration error, not a
	// per-target scope problem, but it's surfaced the same way -- fail
	// before the job is ever marked "running" -- since none of these
	// depend on anything persisted so far.
	enumerator, err := discovery.NewEnumerator(p.DiscoveryBackend, p.Wordlist, p.Resolver, p.Concurrency.DNSWorkers, logger)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: selecting discovery backend: %w", err))
	}
	recordEnumerator, err := dns.NewRecordEnumerator(p.DNSBackend, p.Resolver, logger)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: selecting dns backend: %w", err))
	}
	portScanner, err := ports.NewScanner(p.PortsBackend, validator, p.PortDialTimeout, p.Concurrency.PortWorkers, p.PortLimiter, logger)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: selecting ports backend: %w", err))
	}
	prober, err := httpstage.NewProberForBackend(p.HTTPBackend, validator, p.Resolver, p.HTTPConfig, p.HTTPLimiter, logger)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: selecting http backend: %w", err))
	}
	dialer := safedial.New(validator, p.Resolver)
	crawl, err := crawler.NewCrawlerForBackend(p.CrawlBackend, dialer, logger)
	if err != nil {
		return p.fail(ctx, job, fmt.Errorf("orchestration: selecting crawl backend: %w", err))
	}

	job.Status = models.ScanJobStatusRunning
	if err := p.Store.ScanJobs().Create(ctx, job); err != nil {
		return job, fmt.Errorf("orchestration: creating scan job: %w", err)
	}
	logger.Info("scan started", slog.Int("target_count", len(targets)))

	portList := opts.Ports
	if len(portList) == 0 {
		portList = p.DefaultPorts
	}
	portList = dedupInts(portList)

	warnings, stats, runErr := p.runStages(ctx, job.ID, logger, targets, validator, enumerator, recordEnumerator, portScanner, prober, crawl, dialer, portList)
	job.Warnings = warnings
	job.AuthCrawlStats = stats

	// Individual stages treat a per-item cancellation the same as "this
	// particular item just failed" (e.g. "this candidate doesn't
	// resolve") and don't necessarily propagate it as a stage error, so
	// runStages can return nil even when the run was actually cut short.
	// ctx.Err() is the authoritative signal for whether the operator
	// cancelled the scan (or it hit a deadline), regardless of whether
	// every internal stage individually noticed and reported it.
	if runErr == nil && ctx.Err() != nil {
		runErr = ctx.Err()
	}

	finished := time.Now().UTC()
	job.FinishedAt = &finished
	if runErr != nil {
		job.Status = terminalStatusFor(ctx, runErr)
		job.Error = runErr.Error()
		logger.Error("scan ended with error", slog.String("status", string(job.Status)), slog.String("error", runErr.Error()))
	} else {
		job.Status = models.ScanJobStatusCompleted
		logger.Info("scan completed")
	}

	// The final status write must not be tied to ctx: if the operator
	// cancelled the scan, ctx is already Done, and using it here would
	// make the failure to persist the terminal status itself a
	// consequence of the same cancellation -- leaving the job stuck at
	// "running" in the database forever. A short detached context lets
	// this last bookkeeping write complete regardless.
	persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Store.ScanJobs().Update(persistCtx, job); err != nil {
		return job, fmt.Errorf("orchestration: recording final job status: %w", err)
	}
	return job, runErr
}

// terminalStatusFor classifies a pipeline error as Cancelled (the error
// is or wraps a context cancellation/deadline) or Failed (anything
// else), so `scanner status` reports a Ctrl+C'd scan distinctly from a
// genuine failure.
func terminalStatusFor(ctx context.Context, cause error) models.ScanJobStatus {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) || ctx.Err() != nil {
		return models.ScanJobStatusCancelled
	}
	return models.ScanJobStatusFailed
}

func (p *Pipeline) fail(ctx context.Context, job models.ScanJob, cause error) (models.ScanJob, error) {
	finished := time.Now().UTC()
	job.Status = terminalStatusFor(ctx, cause)
	job.Error = cause.Error()
	job.FinishedAt = &finished

	persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Store.ScanJobs().Create(persistCtx, job); err != nil {
		return job, fmt.Errorf("%w (also failed to record job: %v)", cause, err)
	}
	return job, cause
}

func (p *Pipeline) loadTargets(ctx context.Context, ids []string) ([]models.Target, error) {
	targets := make([]models.Target, 0, len(ids))
	for _, id := range ids {
		t, err := p.Store.Targets().Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", id, err)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// runStages executes discovery -> DNS -> ports -> HTTP -> fingerprint for
// every target, persisting incrementally via Store.WithTx so a crash
// partway through does not lose completed work and `scanner status`
// reflects real progress.
func (p *Pipeline) runStages(
	ctx context.Context,
	scanJobID string,
	logger *slog.Logger,
	targets []models.Target,
	validator scope.Validator,
	enumerator discovery.Enumerator,
	recordEnumerator dns.RecordEnumerator,
	portScanner ports.Scanner,
	prober httpstage.Prober,
	crawl crawler.Crawler,
	dialer *safedial.Dialer,
	portList []int,
) ([]string, models.AuthCrawlStats, error) {
	hosts, err := p.discoverAndResolve(ctx, scanJobID, logger, targets, enumerator, recordEnumerator)
	if err != nil {
		return nil, models.AuthCrawlStats{}, err
	}

	services, err := p.scanPorts(ctx, scanJobID, logger, hosts, portScanner, portList)
	if err != nil {
		return nil, models.AuthCrawlStats{}, err
	}

	crawlTargets, err := p.probeAndFingerprint(ctx, scanJobID, logger, services, hosts, prober)
	if err != nil {
		return nil, models.AuthCrawlStats{}, err
	}

	var warnings []string
	var stats models.AuthCrawlStats
	if p.CrawlEnabled {
		warnings, stats, err = p.crawlAndDiscoverEndpoints(ctx, scanJobID, logger, crawlTargets, crawl, dialer)
		if err != nil {
			return nil, models.AuthCrawlStats{}, err
		}
	}

	return warnings, stats, nil
}

// hostRecord pairs a persisted Host with the hostname it should be
// probed as (the original asset name, not the bare IP), so HTTP
// requests use the right Host header / SNI.
type hostRecord struct {
	models.Host
	Hostname string
}

func (p *Pipeline) discoverAndResolve(ctx context.Context, scanJobID string, logger *slog.Logger, targets []models.Target, enumerator discovery.Enumerator, recordEnumerator dns.RecordEnumerator) ([]hostRecord, error) {
	var hosts []hostRecord

	// seenHostnames dedups by normalized hostname across the WHOLE job,
	// not per-target: the same real-world host is commonly discoverable
	// two ways at once (e.g. explicitly targeted AND found again by
	// subdomain enumeration of its parent domain). Without this, both
	// paths persist their own Asset/Host pair for the identical name,
	// and every downstream stage (ports, HTTP, fingerprinting, crawling)
	// redundantly scans it twice under two different Asset IDs.
	seenHostnames := map[string]bool{}
	var duplicatesSkipped int

	for _, t := range targets {
		switch t.Type {
		case models.TargetTypeIP:
			asset := models.Asset{ID: uuid.NewString(), ScanJobID: scanJobID, Name: t.Value, Source: "target", CreatedAt: time.Now().UTC()}
			host := models.Host{ID: uuid.NewString(), ScanJobID: scanJobID, AssetID: asset.ID, IPAddress: t.Value, CreatedAt: time.Now().UTC()}
			if err := p.persistAssetAndHosts(ctx, asset, []models.Host{host}); err != nil {
				return nil, err
			}
			hosts = append(hosts, hostRecord{Host: host, Hostname: t.Value})
			seenHostnames[t.Value] = true

		case models.TargetTypeCIDR:
			ips, err := expandCIDR(t.Value, p.MaxCIDRHosts)
			if err != nil {
				return nil, fmt.Errorf("orchestration: expanding CIDR %q: %w", t.Value, err)
			}
			asset := models.Asset{ID: uuid.NewString(), ScanJobID: scanJobID, Name: t.Value, Source: "cidr-expansion", CreatedAt: time.Now().UTC()}
			var cidrHosts []models.Host
			for _, ip := range ips {
				cidrHosts = append(cidrHosts, models.Host{ID: uuid.NewString(), ScanJobID: scanJobID, AssetID: asset.ID, IPAddress: ip, CreatedAt: time.Now().UTC()})
			}
			if err := p.persistAssetAndHosts(ctx, asset, cidrHosts); err != nil {
				return nil, err
			}
			for _, h := range cidrHosts {
				hosts = append(hosts, hostRecord{Host: h, Hostname: h.IPAddress})
			}

		case models.TargetTypeHost, models.TargetTypeDomain:
			if name := normalizeHostname(t.Value); seenHostnames[name] {
				duplicatesSkipped++
			} else {
				seenHostnames[name] = true
				resolved, err := p.resolveAndPersist(ctx, scanJobID, t.Value, "target", recordEnumerator)
				if err != nil {
					logger.Warn("failed to resolve target", slog.String("target", t.Value), slog.String("error", err.Error()))
				} else {
					hosts = append(hosts, resolved...)
				}
			}

			if t.Type == models.TargetTypeDomain {
				enumHosts, skipped, err := p.enumerateSubdomains(ctx, scanJobID, logger, t.Value, enumerator, recordEnumerator, seenHostnames)
				duplicatesSkipped += skipped
				if err != nil {
					logger.Warn("subdomain enumeration failed", slog.String("target", t.Value), slog.String("error", err.Error()))
				} else {
					hosts = append(hosts, enumHosts...)
				}
			}
		}
	}

	logger.Info("discovery complete", slog.Int("host_count", len(hosts)), slog.Int("duplicate_hostnames_skipped", duplicatesSkipped))
	return hosts, nil
}

// normalizeHostname lowercases h and strips a trailing DNS root dot, so
// "Example.com", "example.com", and "example.com." are all recognized
// as the same name for discoverAndResolve's dedup-by-hostname check.
// target.Parse already normalizes target-supplied values this way, but
// names arriving from discovery.Candidate (wordlist/subfinder output)
// are not guaranteed to be, so this is applied uniformly at the point of
// comparison rather than trusted to already hold.
func normalizeHostname(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (p *Pipeline) persistAssetAndHosts(ctx context.Context, asset models.Asset, hosts []models.Host) error {
	return p.Store.WithTx(ctx, func(tx storage.Store) error {
		if err := tx.Assets().Create(ctx, asset); err != nil {
			return err
		}
		for _, h := range hosts {
			if err := tx.Hosts().Create(ctx, h); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *Pipeline) resolveAndPersist(ctx context.Context, scanJobID, name, source string, recordEnumerator dns.RecordEnumerator) ([]hostRecord, error) {
	ips, err := p.Resolver.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}

	asset := models.Asset{ID: uuid.NewString(), ScanJobID: scanJobID, Name: name, Source: source, CreatedAt: time.Now().UTC()}
	var dbHosts []models.Host
	for _, ip := range ips {
		dbHosts = append(dbHosts, models.Host{ID: uuid.NewString(), ScanJobID: scanJobID, AssetID: asset.ID, IPAddress: ip.String(), CreatedAt: time.Now().UTC()})
	}
	if err := p.persistAssetHostsAndDNSRecords(ctx, asset, dbHosts, recordEnumerator); err != nil {
		return nil, err
	}

	records := make([]hostRecord, len(dbHosts))
	for i, h := range dbHosts {
		records[i] = hostRecord{Host: h, Hostname: name}
	}
	return records, nil
}

// persistAssetHostsAndDNSRecords persists asset+hosts exactly like
// persistAssetAndHosts, then -- if enabled -- looks up and persists
// CNAME/MX/TXT/NS records for asset.Name via recordEnumerator (native or
// dnsx-backed, per p.DNSBackend). Only call this where asset.Name is a
// genuine hostname (never a bare IP literal, e.g. the TargetTypeIP/CIDR
// paths, which use persistAssetAndHosts directly).
func (p *Pipeline) persistAssetHostsAndDNSRecords(ctx context.Context, asset models.Asset, hosts []models.Host, recordEnumerator dns.RecordEnumerator) error {
	if err := p.persistAssetAndHosts(ctx, asset, hosts); err != nil {
		return err
	}
	if !p.EnumerateDNSRecords {
		return nil
	}
	now := time.Now().UTC()
	for _, r := range recordEnumerator.LookupRecords(ctx, asset.Name) {
		record := models.DNSRecord{ID: uuid.NewString(), ScanJobID: asset.ScanJobID, AssetID: asset.ID, Type: r.Type, Value: r.Value, Priority: r.Priority, CreatedAt: now}
		if err := p.Store.DNSRecords().Create(ctx, record); err != nil {
			return fmt.Errorf("orchestration: persisting dns record for %q: %w", asset.Name, err)
		}
	}
	return nil
}

// enumerateSubdomains discovers candidates for domain and persists the
// ones not already covered by seenHostnames (mutated in place -- shared
// with the caller's whole-job dedup set, see discoverAndResolve). It
// returns the persisted hosts and how many candidates were skipped as
// duplicates.
func (p *Pipeline) enumerateSubdomains(ctx context.Context, scanJobID string, logger *slog.Logger, domain string, enumerator discovery.Enumerator, recordEnumerator dns.RecordEnumerator, seenHostnames map[string]bool) ([]hostRecord, int, error) {
	out := make(chan discovery.Candidate, 64)
	errCh := make(chan error, 1)

	go func() {
		errCh <- enumerator.Enumerate(ctx, domain, out)
		close(out)
	}()

	var hosts []hostRecord
	var duplicatesSkipped int
	for candidate := range out {
		name := normalizeHostname(candidate.Name)
		if seenHostnames[name] {
			duplicatesSkipped++
			continue
		}
		seenHostnames[name] = true

		asset := models.Asset{ID: uuid.NewString(), ScanJobID: scanJobID, Name: candidate.Name, Source: candidate.Source, CreatedAt: time.Now().UTC()}
		var dbHosts []models.Host
		for _, ipStr := range candidate.IPs {
			dbHosts = append(dbHosts, models.Host{ID: uuid.NewString(), ScanJobID: scanJobID, AssetID: asset.ID, IPAddress: ipStr, CreatedAt: time.Now().UTC()})
		}
		if err := p.persistAssetHostsAndDNSRecords(ctx, asset, dbHosts, recordEnumerator); err != nil {
			logger.Warn("failed to persist discovered asset", slog.String("asset", candidate.Name), slog.String("error", err.Error()))
			continue
		}
		for _, h := range dbHosts {
			hosts = append(hosts, hostRecord{Host: h, Hostname: candidate.Name})
		}
	}

	if err := <-errCh; err != nil {
		return hosts, duplicatesSkipped, err
	}
	return hosts, duplicatesSkipped, nil
}

// expandCIDR returns every host IP in cidr, erroring if the range
// contains more than maxHosts addresses -- Phase 1 has no reason to
// support scanning enormous ranges, and a hard cap keeps an operator
// typo (e.g. a /8) from turning into an unbounded scan.
func expandCIDR(cidr string, maxHosts int) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if maxHosts <= 0 {
		maxHosts = 256
	}

	var ips []string
	for addr := ip.Mask(ipNet.Mask); ipNet.Contains(addr); incIP(addr) {
		cp := make(net.IP, len(addr))
		copy(cp, addr)
		ips = append(ips, cp.String())
		if len(ips) > maxHosts {
			return nil, fmt.Errorf("CIDR contains more than %d addresses; supply a smaller range for Phase 1", maxHosts)
		}
	}
	return ips, nil
}

// dedupInts returns ports with duplicates removed, preserving first-seen
// order. A repeated port number (an operator typo in --ports, or a
// custom port list that happens to overlap the configured defaults) must
// scan that port once, not once per occurrence -- otherwise every stage
// downstream (port scan, HTTP probe, fingerprinting) redundantly repeats
// its work and persists duplicate Service/HTTPService rows for what is
// really one open port.
func dedupInts(ports []int) []int {
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func (p *Pipeline) scanPorts(ctx context.Context, scanJobID string, logger *slog.Logger, hosts []hostRecord, scanner ports.Scanner, portList []int) ([]models.Service, error) {
	var (
		mu       sync.Mutex
		services []models.Service
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency.PortWorkers)

	for _, h := range hosts {
		h := h
		g.Go(func() error {
			ip := net.ParseIP(h.IPAddress)
			if ip == nil {
				return nil
			}
			results, err := scanner.Scan(gctx, h.Hostname, ip, portList)
			if err != nil {
				logger.Warn("port scan skipped", slog.String("host", h.IPAddress), slog.String("error", err.Error()))
				return nil
			}
			for r := range results {
				if !r.Open || r.Error != nil {
					continue
				}
				svc := models.Service{ID: uuid.NewString(), ScanJobID: scanJobID, HostID: h.ID, Port: r.Port, Protocol: "tcp", CreatedAt: time.Now().UTC()}
				if err := p.Store.Services().Create(gctx, svc); err != nil {
					return err
				}
				mu.Lock()
				services = append(services, svc)
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return services, err
	}
	logger.Info("port scan complete", slog.Int("open_service_count", len(services)))
	return services, nil
}

// crawlTarget carries what crawlAndDiscoverEndpoints needs to crawl a
// successfully-probed HTTPService: the exact scope-validated IP/port and
// the hostname to present (Host header / SNI), matching the resolve-
// validate-dial-by-IP discipline used everywhere else.
type crawlTarget struct {
	httpServiceID string
	ip            net.IP
	port          int
	hostname      string
	scheme        string
}

func (p *Pipeline) probeAndFingerprint(ctx context.Context, scanJobID string, logger *slog.Logger, services []models.Service, hosts []hostRecord, prober httpstage.Prober) ([]crawlTarget, error) {
	hostnameByID := make(map[string]string, len(hosts))
	ipByID := make(map[string]string, len(hosts))
	for _, h := range hosts {
		hostnameByID[h.ID] = h.Hostname
		ipByID[h.ID] = h.IPAddress
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency.HTTPWorkers)

	var (
		httpCount, techCount atomic.Int64
		mu                   sync.Mutex
		crawlTargets         []crawlTarget
	)

	for _, svc := range services {
		svc := svc
		g.Go(func() error {
			ip := net.ParseIP(ipByID[svc.HostID])
			if ip == nil {
				return nil
			}
			hostname := hostnameByID[svc.HostID]

			httpSvc, body, err := prober.Probe(gctx, ip, svc.Port, hostname)
			if err != nil {
				return nil // not every open port speaks HTTP; not a scan error
			}
			httpSvc.ID = uuid.NewString()
			httpSvc.ScanJobID = scanJobID
			httpSvc.ServiceID = svc.ID
			httpSvc.CreatedAt = time.Now().UTC()

			if err := p.Store.HTTPServices().Create(gctx, *httpSvc); err != nil {
				return err
			}
			httpCount.Add(1)

			mu.Lock()
			crawlTargets = append(crawlTargets, crawlTarget{httpServiceID: httpSvc.ID, ip: ip, port: svc.Port, hostname: hostname, scheme: httpSvc.Scheme})
			mu.Unlock()

			techs := p.Fingerprinter.Identify(headerToHTTPHeader(httpSvc.Headers), body)
			for _, tech := range techs {
				tech.ID = uuid.NewString()
				tech.ScanJobID = scanJobID
				tech.HTTPServiceID = httpSvc.ID
				tech.CreatedAt = time.Now().UTC()
				if err := p.Store.Technologies().Create(gctx, tech); err != nil {
					return err
				}
				techCount.Add(1)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	logger.Info("http probing complete", slog.Int64("http_service_count", httpCount.Load()), slog.Int64("technology_count", techCount.Load()))
	return crawlTargets, nil
}

// crawlAndDiscoverEndpoints crawls each successfully-probed HTTPService
// (bounded by p.CrawlMaxDepth/p.CrawlMaxPages), persists the normalized
// results as Endpoints, and fingerprints every same-origin script the
// crawl turned up. A single target's crawl failing (a broken/unreachable
// service) is logged and skipped, not fatal to the job -- matching the
// same resilience pattern as DNS/subdomain lookups.
func (p *Pipeline) crawlAndDiscoverEndpoints(ctx context.Context, scanJobID string, logger *slog.Logger, targets []crawlTarget, crawl crawler.Crawler, dialer *safedial.Dialer) ([]string, models.AuthCrawlStats, error) {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency.HTTPWorkers)

	var endpointCount, jsTechCount, inputCount, inputDuplicateCount, inputWarningCount atomic.Int64
	var publicPages, authenticatedPages, authenticatedEndpoints atomic.Int64
	var sessionExpired atomic.Bool
	var warningsMu sync.Mutex
	var warnings []string

	logger.Info("input_discovery_started", slog.String("scan_job_id", scanJobID))

	for _, target := range targets {
		target := target
		g.Go(func() error {
			jar := p.AuthSession.JarFor(target.hostname)
			headers := p.AuthSession.HeadersFor(target.hostname)
			// A target's crawl is "authenticated" if EITHER session
			// mechanism applies to its host -- uniform for every page
			// this one Crawl call fetches (a session, if any, is
			// established once per target, not varied per page).
			authenticated := jar != nil || len(headers) > 0
			// identityName is Phase 3.16's own addition: the configured
			// IDENTITY name (if any) this target's crawl authenticated
			// as -- stamped onto every Endpoint/Parameter this target
			// produces below (task section 7's "identity context on
			// discovered data"). Empty for an unauthenticated crawl, and
			// also empty for a session authenticated via a bare
			// --auth-profile with no identity wrapper (Session.IdentityName
			// is only ever set by cmd/scanner when it resolved an
			// Identity -- see docs/phase-3-16-multi-identity.md).
			var identityName string
			if authenticated {
				identityName = p.AuthSession.IdentityName
			}

			pages, err := crawl.Crawl(gctx, target.ip, target.port, target.hostname, target.scheme, "/", crawler.Options{
				MaxDepth:     p.CrawlMaxDepth,
				MaxPages:     p.CrawlMaxPages,
				Timeout:      p.HTTPConfig.Timeout,
				Jar:          jar,
				ExtraHeaders: headers,
			})
			if err != nil {
				logger.Warn("crawl skipped", slog.String("host", target.hostname), slog.Int("port", target.port), slog.String("error", err.Error()))
				return nil
			}

			if authenticated {
				authenticatedPages.Add(int64(len(pages)))
				if detectSessionExpired(pages) {
					sessionExpired.Store(true)
					logger.Warn("auth_session_possibly_expired",
						slog.String("scan_job_id", scanJobID), slog.String("host", target.hostname),
						slog.String("profile", p.AuthSession.ProfileName))
					warningsMu.Lock()
					warnings = append(warnings, fmt.Sprintf("%s: authenticated session appears to have expired mid-crawl (401/403 or login-page redirect observed) -- results reflect what was reachable before expiration", target.hostname))
					warningsMu.Unlock()
				}
			} else {
				publicPages.Add(int64(len(pages)))
			}

			// endpointIDByKey correlates each parameters.Candidate back
			// to the Endpoint row it belongs to: both endpoints.Normalize
			// and parameters.Normalize compute the identical
			// (path, method, source) identity from the SAME pages, so a
			// Candidate's own triple always matches exactly one entry
			// created here.
			endpointIDByKey := make(map[string]string)
			// pathEndpoints (Phase 3.23) mirrors the SAME
			// endpoints.Normalize(pages) output this loop already
			// persists -- collected here, not via a second Normalize
			// call, so path inference sees exactly the endpoints THIS
			// crawl target (one HTTPService) discovered, never pooled
			// across services (see docs/phase-3-23-path-parameters.md
			// section 1.4 for why cross-service pooling would be a
			// real correctness bug).
			var pathEndpoints []parameters.PathEndpoint
			for _, e := range endpoints.Normalize(pages) {
				e.ID = uuid.NewString()
				e.ScanJobID = scanJobID
				e.HTTPServiceID = target.httpServiceID
				e.IdentityContext = identityName
				e.CreatedAt = time.Now().UTC()
				if err := p.Store.Endpoints().Create(gctx, e); err != nil {
					return err
				}
				endpointCount.Add(1)
				if authenticated {
					authenticatedEndpoints.Add(1)
				}
				endpointIDByKey[e.Path+"\x00"+e.Method+"\x00"+e.Source] = e.ID
				pathEndpoints = append(pathEndpoints, parameters.PathEndpoint{Path: e.Path, Method: e.Method, Source: e.Source})
			}

			// Input discovery (Phase 3.13) reuses these SAME already-
			// fetched pages -- no additional network request is made to
			// discover a single input (task's explicit "discovery must
			// not become 100 inputs -> 100 network requests").
			inputRes := parameters.Normalize(pages, p.ParameterLimits)
			inputDuplicateCount.Add(int64(inputRes.DuplicateCount))
			for _, w := range inputRes.Warnings {
				inputWarningCount.Add(1)
				logger.Warn("input_discovery_warning", slog.String("scan_job_id", scanJobID), slog.String("host", target.hostname), slog.String("warning", w))
				warningsMu.Lock()
				warnings = append(warnings, fmt.Sprintf("%s: %s", target.hostname, w))
				warningsMu.Unlock()
			}
			for _, c := range inputRes.Candidates {
				endpointID, ok := endpointIDByKey[c.EndpointPath+"\x00"+c.EndpointMethod+"\x00"+c.EndpointSource]
				if !ok {
					continue // defensive: unreachable given both Normalize calls derive identity from the same pages, but never worth failing the whole crawl over
				}
				param := models.Parameter{
					ID: uuid.NewString(), ScanJobID: scanJobID, EndpointID: endpointID,
					Name: c.Name, Location: string(c.Location), Classification: string(parameters.ClassificationFor(c.Location)),
					Method: c.EndpointMethod, Value: c.Value, Source: c.Source, ContentType: c.ContentType,
					IdentityContext: identityName, Provenance: string(c.Provenance), Hidden: c.FieldType == "hidden",
					CreatedAt: time.Now().UTC(),
				}
				if err := p.Store.Parameters().Create(gctx, param); err != nil {
					return err
				}
				inputCount.Add(1)
			}

			// Phase 3.18: live JSON RESPONSE-body discovery -- reuses
			// the SAME already-fetched pages, no additional network
			// request (identical discipline to the query/form
			// discovery above). Every resulting Candidate carries
			// Provenance == ProvenanceResponseField -- see
			// docs/phase-3-18-api-json-discovery.md section 3.
			jsonRes := parameters.NormalizeJSONResponses(pages, p.ParameterLimits)
			inputDuplicateCount.Add(int64(jsonRes.DuplicateCount))
			for _, w := range jsonRes.Warnings {
				inputWarningCount.Add(1)
				logger.Warn("json_response_discovery_warning", slog.String("scan_job_id", scanJobID), slog.String("host", target.hostname), slog.String("warning", w))
				warningsMu.Lock()
				warnings = append(warnings, fmt.Sprintf("%s: %s", target.hostname, w))
				warningsMu.Unlock()
			}
			for _, c := range jsonRes.Candidates {
				endpointID, ok := endpointIDByKey[c.EndpointPath+"\x00"+c.EndpointMethod+"\x00"+c.EndpointSource]
				if !ok {
					continue
				}
				param := models.Parameter{
					ID: uuid.NewString(), ScanJobID: scanJobID, EndpointID: endpointID,
					Name: c.Name, Location: string(c.Location), Classification: string(parameters.ClassificationFor(c.Location)),
					Method: c.EndpointMethod, Value: c.Value, Source: c.Source, ContentType: c.ContentType,
					IdentityContext: identityName, Provenance: string(c.Provenance),
					CreatedAt: time.Now().UTC(),
				}
				if err := p.Store.Parameters().Create(gctx, param); err != nil {
					return err
				}
				inputCount.Add(1)
			}

			// Phase 3.23: path-parameter inference -- reuses the SAME
			// already-persisted endpoint identities gathered above, no
			// additional network request (identical discipline to
			// every other discovery pass in this function). See
			// docs/phase-3-23-path-parameters.md sections 1.3-1.4.
			pathRes := parameters.InferPathInputs(pathEndpoints, p.ParameterLimits)
			inputDuplicateCount.Add(int64(pathRes.DuplicateCount))
			for _, w := range pathRes.Warnings {
				inputWarningCount.Add(1)
				logger.Warn("path_input_discovery_warning", slog.String("scan_job_id", scanJobID), slog.String("host", target.hostname), slog.String("warning", w))
				warningsMu.Lock()
				warnings = append(warnings, fmt.Sprintf("%s: %s", target.hostname, w))
				warningsMu.Unlock()
			}
			for _, c := range pathRes.Candidates {
				endpointID, ok := endpointIDByKey[c.EndpointPath+"\x00"+c.EndpointMethod+"\x00"+c.EndpointSource]
				if !ok {
					continue
				}
				param := models.Parameter{
					ID: uuid.NewString(), ScanJobID: scanJobID, EndpointID: endpointID,
					Name: c.Name, Location: string(c.Location), Classification: string(parameters.ClassificationFor(c.Location)),
					Method: c.EndpointMethod, Value: c.Value, Source: c.Source,
					IdentityContext: identityName, Provenance: string(c.Provenance), PathSegmentIndex: c.PathSegmentIndex,
					CreatedAt: time.Now().UTC(),
				}
				if err := p.Store.Parameters().Create(gctx, param); err != nil {
					return err
				}
				inputCount.Add(1)
			}

			techCount, jsEndpointCount, err := p.discoverJavaScriptTechnologies(gctx, scanJobID, target, pages, dialer, identityName)
			if err != nil {
				return err
			}
			jsTechCount.Add(techCount)
			endpointCount.Add(jsEndpointCount)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, models.AuthCrawlStats{}, err
	}
	logger.Info("crawl complete", slog.Int64("endpoint_count", endpointCount.Load()), slog.Int64("javascript_technology_count", jsTechCount.Load()))
	logger.Info("input_discovery_completed",
		slog.String("scan_job_id", scanJobID),
		slog.Int64("endpoint_count", endpointCount.Load()),
		slog.Int64("input_count", inputCount.Load()),
		slog.Int64("duplicate_count", inputDuplicateCount.Load()),
		slog.Int64("truncated_count", inputWarningCount.Load()),
	)
	sort.Strings(warnings) // deterministic order, independent of goroutine completion order
	stats := models.AuthCrawlStats{
		PublicPages:            int(publicPages.Load()),
		AuthenticatedPages:     int(authenticatedPages.Load()),
		AuthenticatedRequests:  int(authenticatedPages.Load()),
		AuthenticatedEndpoints: int(authenticatedEndpoints.Load()),
		SessionExpired:         sessionExpired.Load(),
	}
	return warnings, stats, nil
}

// detectSessionExpired is task section F's detection logic, applied to
// one target's already-fetched pages (no extra network request): a
// session is treated as possibly expired if any authenticated page
// fetch returned 401/403.
//
// An earlier version of this function ALSO flagged a page whose final
// URL path matched the session's own login page, as a proxy for "the
// target redirected the crawler back to login." That heuristic was
// removed after it produced a false positive proven by
// TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph (lab package):
// harness_auth.go's own root page links to /login (completely ordinary
// -- most real sites do), so an authenticated crawl that simply
// followed that ordinary link -- with a perfectly valid session,
// nothing expired -- was wrongly flagged. Distinguishing "redirected
// BACK to login due to expiration" from "linked to login normally"
// requires knowing each page's PRE-redirect requested path, which
// crawler.Page does not currently retain (only the final,
// post-redirect URL) -- adding that would be a larger, separate
// crawler change. Rather than ship a heuristic proven to false-positive
// on completely normal pages, this function relies solely on the
// unambiguous 401/403 signal -- see
// docs/phase-3-15-authenticated-crawling.md "Session expiration
// policy" and "Known limitations" for both this decision and what a
// more precise future implementation would need.
//
// Deliberately does NOT attempt to re-authenticate or retry -- see the
// doc comment on AuthCrawlStats.SessionExpired for why continuing with
// already-discovered results, flagged by a warning, is this codebase's
// chosen deterministic policy (task's "avoid infinite re-login loops"
// is satisfied by construction: no re-login is ever attempted
// mid-crawl, so no loop can occur).
func detectSessionExpired(pages []crawler.Page) bool {
	for _, pg := range pages {
		if pg.StatusCode == nethttp.StatusUnauthorized || pg.StatusCode == nethttp.StatusForbidden {
			return true
		}
	}
	return false
}

// maxScriptBodySample bounds how much of each fetched script is read,
// matching the rationale behind the crawler's own page body sampling.
const maxScriptBodySample = 512 * 1024

// discoverJavaScriptTechnologies fetches every distinct same-origin
// script referenced across pages and runs each script's body through the
// fingerprinter, persisting any match against target's HTTPService.
// Cross-origin scripts (third-party CDNs, analytics, etc.) are skipped
// entirely, never fetched -- for the same reason the crawler itself never
// follows a cross-origin link: dialing infrastructure the operator did
// not authorize as a target is out of bounds even when scope.Validator
// would ultimately refuse the connection anyway. A single unreachable or
// unparseable script is skipped, not fatal to the crawl.
func (p *Pipeline) discoverJavaScriptTechnologies(ctx context.Context, scanJobID string, target crawlTarget, pages []crawler.Page, dialer *safedial.Dialer, identityName string) (techCount int64, endpointCount int64, err error) {
	origin := fmt.Sprintf("%s:%d", target.hostname, target.port)
	client := dialer.NewClient(target.hostname, target.ip, nil, nil, p.HTTPConfig.Timeout, 3)

	seen := map[string]bool{}
	seenRoute := map[string]bool{}
	for _, page := range pages {
		for _, scriptURL := range page.Scripts {
			if seen[scriptURL] {
				continue
			}
			seen[scriptURL] = true

			u, err := url.Parse(scriptURL)
			if err != nil || u.Host != origin {
				continue
			}

			headers, body, err := fetchScript(ctx, client, scriptURL)
			if err != nil {
				continue
			}

			for _, tech := range p.Fingerprinter.Identify(headers, body) {
				tech.ID = uuid.NewString()
				tech.ScanJobID = scanJobID
				tech.HTTPServiceID = target.httpServiceID
				tech.CreatedAt = time.Now().UTC()
				if err := p.Store.Technologies().Create(ctx, tech); err != nil {
					return techCount, endpointCount, err
				}
				techCount++
			}

			// Phase 3.18: conservative API route extraction from the
			// SAME already-fetched script body -- no second fetch. See
			// docs/phase-3-18-api-json-discovery.md section 5.
			for _, route := range endpoints.ExtractAPIRoutes(body, u, endpoints.DefaultJSLimits()) {
				if seenRoute[route] {
					continue
				}
				seenRoute[route] = true

				routeURL, err := url.Parse(route)
				if err != nil {
					continue
				}
				if routeURL.IsAbs() {
					// Centralized scope check BEFORE this reference is
					// ever persisted as an Endpoint candidate -- an
					// out-of-scope absolute reference is simply
					// dropped, never recorded as an authorized target
					// (task section 11's "must NOT turn it into an
					// authorized scan target").
					decision, err := dialer.Validator.CheckHost(ctx, routeURL.Hostname())
					if err != nil || !decision.Allowed {
						continue
					}
				}

				e := models.Endpoint{
					ID: uuid.NewString(), ScanJobID: scanJobID, HTTPServiceID: target.httpServiceID,
					Path: endpoints.PathOf(route), Method: nethttp.MethodGet, Source: endpoints.SourceJavaScriptRoute,
					IdentityContext: identityName,
					APICandidate:    true, APIEvidence: endpoints.EvidenceJavaScriptReference,
					CreatedAt: time.Now().UTC(),
				}
				if err := p.Store.Endpoints().Create(ctx, e); err != nil {
					return techCount, endpointCount, err
				}
				endpointCount++
			}
		}
	}
	return techCount, endpointCount, nil
}

func fetchScript(ctx context.Context, client *nethttp.Client, scriptURL string) (nethttp.Header, []byte, error) {
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, scriptURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("orchestration: build script request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("orchestration: fetch script %s: %w", scriptURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBodySample))
	if err != nil {
		return nil, nil, fmt.Errorf("orchestration: read script %s: %w", scriptURL, err)
	}
	return resp.Header, body, nil
}

// headerToHTTPHeader converts the flattened map[string]string a
// models.HTTPService stores back into an http.Header for
// fingerprint.Fingerprinter, which matches against canonical header
// names/values.
func headerToHTTPHeader(headers map[string]string) nethttp.Header {
	h := nethttp.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return h
}
