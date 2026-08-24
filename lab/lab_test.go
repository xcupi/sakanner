// Integration tests that run sakanner's real orchestration.Pipeline
// against the lab and compare its results against ground-truth.yaml --
// never against the scanner's own prior output. DNS resolution for
// these tests goes through the lab's dns.FakeResolver (see harness.go
// and docs/phase-2-test-lab.md "DNS / hostnames" for why), everything
// else is the genuine production pipeline: real scope enforcement, real
// TCP dials, real HTTP(S) requests, real crawling, real fingerprinting,
// real SQLite persistence.
package lab

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/orchestration"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// runLabScan starts the lab, scans every in-scope host from ground
// truth in one job, and returns the completed job plus the store it was
// persisted to for assertions.
func runLabScan(t *testing.T) (*Lab, storage.Store, models.ScanJob) {
	t.Helper()
	l := testLab(t)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	var targetIDs []string
	for _, host := range l.GT.Scope.InScope {
		id := uuid.NewString()
		if err := store.Targets().Create(ctx, models.Target{ID: id, Value: host, Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("create target %s: %v", host, err)
		}
		if err := store.ScopeRules().Create(ctx, models.ScopeRule{ID: uuid.NewString(), Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("create scope rule %s: %v", host, err)
		}
		targetIDs = append(targetIDs, id)
	}

	p := &orchestration.Pipeline{
		Store:         store,
		Resolver:      l.Resolver,
		Fingerprinter: fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:  l.Ports(),
		// 1s is comfortably longer than every fast lab service's real
		// (sub-millisecond, loopback) response time, and comfortably
		// shorter than SlowResponseDelay -- so slow.scanner.test times
		// out deterministically without making the other services flaky.
		PortDialTimeout:     1 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 1 * time.Second, MaxRedirects: 5},
		PortLimiter:         rate.NewLimiter(rate.Limit(200), 200),
		HTTPLimiter:         rate.NewLimiter(rate.Limit(200), 200),
		Concurrency:         orchestration.Concurrency{DNSWorkers: 8, PortWorkers: 16, HTTPWorkers: 8},
		AllowReservedRanges: true, // every lab host is on 127.0.0.0/8 or ::1, which are reserved ranges
		MaxCIDRHosts:        256,
		EnumerateDNSRecords: true,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       20,
		Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
	}

	job, err := p.Run(ctx, orchestration.RunOptions{TargetIDs: targetIDs})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	return l, store, job
}

// TestLab_FullPipelineAgainstGroundTruth is the lab's central
// integration test: one scan of every in-scope lab host, with every
// sub-test below asserting a different ground-truth fact against that
// single scan's persisted results. Sub-tests share one scan (rather than
// each starting their own lab + running their own scan) so the whole
// suite stays fast and so "the scan completed at all, covering
// everything at once" is itself part of what's being proven.
func TestLab_FullPipelineAgainstGroundTruth(t *testing.T) {
	l, store, job := runLabScan(t)
	ctx := context.Background()

	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s) -- a slow/refused/out-of-scope host must not prevent the job from completing", job.Status, job.Error)
	}

	assets, err := store.Assets().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Assets().ListByScanJob: %v", err)
	}
	hosts, err := store.Hosts().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Hosts().ListByScanJob: %v", err)
	}
	services, err := store.Services().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Services().ListByScanJob: %v", err)
	}
	httpServices, err := store.HTTPServices().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("HTTPServices().ListByScanJob: %v", err)
	}
	technologies, err := store.Technologies().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Technologies().ListByScanJob: %v", err)
	}
	endpoints, err := store.Endpoints().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("Endpoints().ListByScanJob: %v", err)
	}
	dnsRecords, err := store.DNSRecords().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("DNSRecords().ListByScanJob: %v", err)
	}

	assetByName := map[string]models.Asset{}
	for _, a := range assets {
		assetByName[a.Name] = a
	}
	hostsByAssetID := map[string][]models.Host{}
	for _, h := range hosts {
		hostsByAssetID[h.AssetID] = append(hostsByAssetID[h.AssetID], h)
	}
	techByHTTPService := map[string][]models.Technology{}
	for _, tech := range technologies {
		techByHTTPService[tech.HTTPServiceID] = append(techByHTTPService[tech.HTTPServiceID], tech)
	}
	endpointsByHTTPService := map[string][]models.Endpoint{}
	for _, e := range endpoints {
		endpointsByHTTPService[e.HTTPServiceID] = append(endpointsByHTTPService[e.HTTPServiceID], e)
	}

	// --- 1 & 11. Expected assets discovered, and persisted correctly ---
	t.Run("expected_assets_discovered", func(t *testing.T) {
		for _, host := range l.GT.Scope.InScope {
			a, ok := assetByName[host]
			if !ok {
				t.Errorf("no Asset persisted for in-scope host %q", host)
				continue
			}
			wantIP := l.GT.DNS[host]
			if wantIP.A == "" && wantIP.AAAA == "" {
				continue // CNAME entries (e.g. www.scanner.test) checked separately below
			}
			hs := hostsByAssetID[a.ID]
			if len(hs) != 1 {
				t.Errorf("host %q: got %d Host rows, want 1: %+v", host, len(hs), hs)
				continue
			}
			wantAddr := wantIP.A
			if wantAddr == "" {
				wantAddr = wantIP.AAAA
			}
			if hs[0].IPAddress != wantAddr {
				t.Errorf("host %q: IPAddress = %q, want %q", host, hs[0].IPAddress, wantAddr)
			}
		}
	})

	// --- 8. Out-of-scope targets are not actively scanned ------------
	t.Run("out_of_scope_never_scanned", func(t *testing.T) {
		for _, host := range l.GT.Scope.OutOfScope {
			if _, ok := assetByName[host]; ok {
				t.Errorf("out-of-scope host %q has an Asset row -- it must never be scanned", host)
			}
		}
	})

	// --- 2. Expected services (open ports) discovered -----------------
	t.Run("expected_services_discovered", func(t *testing.T) {
		scannerAsset := assetByName["scanner.test"]
		scannerHosts := hostsByAssetID[scannerAsset.ID]
		if len(scannerHosts) != 1 {
			t.Fatalf("scanner.test hosts = %+v, want exactly 1", scannerHosts)
		}
		var open int
		for _, svc := range services {
			if svc.HostID == scannerHosts[0].ID {
				open++
			}
		}
		if open != 1 {
			t.Errorf("scanner.test open service count = %d, want 1", open)
		}
	})

	t.Run("refuse_scanner_test_has_no_open_service", func(t *testing.T) {
		refuseAsset, ok := assetByName["refuse.scanner.test"]
		if !ok {
			t.Fatal("no Asset for refuse.scanner.test")
		}
		refuseHosts := hostsByAssetID[refuseAsset.ID]
		if len(refuseHosts) != 1 {
			t.Fatalf("refuse.scanner.test hosts = %+v, want exactly 1", refuseHosts)
		}
		for _, svc := range services {
			if svc.HostID == refuseHosts[0].ID {
				t.Errorf("refuse.scanner.test has an open service %+v, want none (connection refused)", svc)
			}
		}
	})

	// --- 4. Expected technologies detected where supported -------------
	t.Run("expected_technologies_detected", func(t *testing.T) {
		for _, host := range []string{"scanner.test", "www.scanner.test", "api.scanner.test"} {
			svcGT, ok := l.GT.Services[host]
			if !ok || svcGT.ExpectedTechnology == nil {
				continue
			}
			httpSvc, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, host)
			if !found {
				t.Errorf("no HTTPService found for %q", host)
				continue
			}
			techs := techByHTTPService[httpSvc.ID]
			var match *models.Technology
			for i := range techs {
				if techs[i].Name == svcGT.ExpectedTechnology.Name {
					match = &techs[i]
				}
			}
			if match == nil {
				t.Errorf("%s: no Technology named %q found among %+v", host, svcGT.ExpectedTechnology.Name, techs)
				continue
			}
			if match.Version != svcGT.ExpectedTechnology.Version {
				t.Errorf("%s: Technology %s Version = %q, want %q", host, match.Name, match.Version, svcGT.ExpectedTechnology.Version)
			}
		}
	})

	t.Run("static_scanner_test_has_no_technology", func(t *testing.T) {
		httpSvc, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "static.scanner.test")
		if !found {
			t.Fatal("no HTTPService found for static.scanner.test")
		}
		if techs := techByHTTPService[httpSvc.ID]; len(techs) != 0 {
			t.Errorf("static.scanner.test technologies = %+v, want none (no Server header, negative case)", techs)
		}
	})

	// --- 3, 6 & 7. Expected endpoints, JS files, dedup ------------------
	t.Run("scanner_test_endpoints_deduplicated", func(t *testing.T) {
		httpSvc, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "scanner.test")
		if !found {
			t.Fatal("no HTTPService found for scanner.test")
		}
		eps := endpointsByHTTPService[httpSvc.ID]
		want := l.GT.Services["scanner.test"].EndpointCount
		if len(eps) != want {
			t.Errorf("scanner.test endpoint count = %d, want %d (two links to /about must dedup to one): %+v", len(eps), want, eps)
		}

		var haveJS, haveQuery, haveForm bool
		for _, e := range eps {
			if e.Source == "javascript" && e.Path == "/static/app.js" {
				haveJS = true
			}
			if e.Path == "/search?q=test&sort=asc" {
				haveQuery = true
			}
			if e.Source == "form" && e.Method == "POST" && e.Path == "/contact" {
				haveForm = true
			}
		}
		if !haveJS {
			t.Error("scanner.test: no javascript-sourced endpoint for /static/app.js")
		}
		if !haveQuery {
			t.Error("scanner.test: no endpoint preserving the /search query string")
		}
		if !haveForm {
			t.Error("scanner.test: no POST /contact form endpoint")
		}

		techs := techByHTTPService[httpSvc.ID]
		var haveJQuery bool
		for _, tech := range techs {
			if tech.Name == "jQuery" && tech.Version == "3.6.0" {
				haveJQuery = true
			}
		}
		if !haveJQuery {
			t.Errorf("scanner.test: no jQuery 3.6.0 Technology from JavaScript discovery, got %+v", techs)
		}
	})

	t.Run("api_scanner_test_endpoints_match_ground_truth", func(t *testing.T) {
		httpSvc, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "api.scanner.test")
		if !found {
			t.Fatal("no HTTPService found for api.scanner.test")
		}
		eps := endpointsByHTTPService[httpSvc.ID]
		want := l.GT.Services["api.scanner.test"].EndpointCount
		if len(eps) != want {
			t.Errorf("api.scanner.test endpoint count = %d, want %d: %+v", len(eps), want, eps)
		}
		var haveQuery bool
		for _, e := range eps {
			if e.Path == "/items?category=books&sort=asc" {
				haveQuery = true
			}
		}
		if !haveQuery {
			t.Error("api.scanner.test: no endpoint preserving the /items query string")
		}
	})

	t.Run("js_scanner_test_javascript_discovery", func(t *testing.T) {
		httpSvc, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "js.scanner.test")
		if !found {
			t.Fatal("no HTTPService found for js.scanner.test")
		}
		eps := endpointsByHTTPService[httpSvc.ID]
		want := l.GT.Services["js.scanner.test"].EndpointCount
		if len(eps) != want {
			t.Errorf("js.scanner.test endpoint count = %d, want %d: %+v", len(eps), want, eps)
		}
		techs := techByHTTPService[httpSvc.ID]
		var haveJQuery bool
		for _, tech := range techs {
			if tech.Name == "jQuery" && tech.Version == "3.6.0" {
				haveJQuery = true
			}
		}
		if !haveJQuery {
			t.Errorf("js.scanner.test: no jQuery 3.6.0 Technology from JavaScript discovery, got %+v", techs)
		}
	})

	// --- 9. Timeout targets do not hang the scan ------------------------
	t.Run("slow_scanner_test_times_out_without_http_service", func(t *testing.T) {
		slowAsset, ok := assetByName["slow.scanner.test"]
		if !ok {
			t.Fatal("no Asset for slow.scanner.test")
		}
		slowHosts := hostsByAssetID[slowAsset.ID]
		if len(slowHosts) != 1 {
			t.Fatalf("slow.scanner.test hosts = %+v, want exactly 1", slowHosts)
		}
		var openService *models.Service
		for i := range services {
			if services[i].HostID == slowHosts[0].ID {
				openService = &services[i]
			}
		}
		if openService == nil {
			t.Fatal("slow.scanner.test has no open service -- the TCP port itself should still be discovered even though HTTP probing times out")
		}
		for _, h := range httpServices {
			if h.ServiceID == openService.ID {
				t.Errorf("slow.scanner.test has an HTTPService despite the handler sleeping past the configured timeout: %+v", h)
			}
		}
	})

	// --- non-standard port ------------------------------------------------
	t.Run("altport_scanner_test_discovered_on_explicit_port", func(t *testing.T) {
		if _, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "altport.scanner.test"); !found {
			t.Error("no HTTPService found for altport.scanner.test -- non-standard port scanning did not work")
		}
	})

	// --- DNS: CNAME resolution feeding an in-scope alias ------------------
	t.Run("www_scanner_test_cname_record_persisted", func(t *testing.T) {
		wwwAsset, ok := assetByName["www.scanner.test"]
		if !ok {
			t.Fatal("no Asset for www.scanner.test")
		}
		var found bool
		for _, r := range dnsRecords {
			if r.AssetID == wwwAsset.ID && r.Type == models.DNSRecordTypeCNAME && r.Value == "scanner.test." {
				found = true
			}
		}
		if !found {
			t.Errorf("no CNAME record scanner.test. persisted for www.scanner.test, got %+v", dnsRecords)
		}
	})

	// --- IPv6 (best-effort, see ground-truth.yaml) ----------------------
	t.Run("ipv6_scanner_test_discovered_and_dialed", func(t *testing.T) {
		ipv6Asset, ok := assetByName["ipv6.scanner.test"]
		if !ok {
			t.Skip("ipv6.scanner.test not resolved -- IPv6 unavailable in this sandbox, which is an accepted best-effort limitation")
		}
		ipv6Hosts := hostsByAssetID[ipv6Asset.ID]
		if len(ipv6Hosts) != 1 || ipv6Hosts[0].IPAddress != "::1" {
			t.Fatalf("ipv6.scanner.test hosts = %+v, want exactly 1 with IPAddress=::1", ipv6Hosts)
		}
		if _, found := findHTTPServiceForHost(t, store, ctx, job.ID, assetByName, hostsByAssetID, "ipv6.scanner.test"); !found {
			t.Error("no HTTPService found for ipv6.scanner.test -- IPv6 dial/probe did not work")
		}
	})
}

// findHTTPServiceForHost locates the HTTPService belonging to host's
// single discovered Service, if any.
func findHTTPServiceForHost(t *testing.T, store storage.Store, ctx context.Context, scanJobID string, assetByName map[string]models.Asset, hostsByAssetID map[string][]models.Host, host string) (models.HTTPService, bool) {
	t.Helper()
	asset, ok := assetByName[host]
	if !ok {
		return models.HTTPService{}, false
	}
	hostsForAsset := hostsByAssetID[asset.ID]
	if len(hostsForAsset) != 1 {
		return models.HTTPService{}, false
	}
	services, err := store.Services().ListByScanJob(ctx, scanJobID)
	if err != nil {
		t.Fatalf("Services().ListByScanJob: %v", err)
	}
	httpServices, err := store.HTTPServices().ListByScanJob(ctx, scanJobID)
	if err != nil {
		t.Fatalf("HTTPServices().ListByScanJob: %v", err)
	}
	for _, svc := range services {
		if svc.HostID != hostsForAsset[0].ID {
			continue
		}
		for _, h := range httpServices {
			if h.ServiceID == svc.ID {
				return h, true
			}
		}
	}
	return models.HTTPService{}, false
}
