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

	"sakanner/internal/dns"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// TestRun_DataSurvivesStoreRestart runs a real scan against a
// file-backed (not :memory:) SQLite database -- touching every major
// table a Phase 2 scan can populate (assets, hosts, DNS records,
// services, HTTP services, technologies, endpoints) -- then closes that
// Store (simulating the scanner process stopping) and opens a brand NEW
// Store instance against the same database file (simulating a restart),
// and verifies every piece of data is still retrievable and unchanged.
func TestRun_DataSurvivesStoreRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sakanner.db")

	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write([]byte(`<html><head><title>Restart Test</title></head><body>
			<a href="/about">About</a>
			<script src="/app.js"></script>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("about page"))
	})
	mux.HandleFunc("/app.js", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("/*! jQuery JavaScript Library v3.6.0 */"))
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

	ctx := context.Background()

	// --- Phase A: run the scan, then stop (close) the store. ---
	var jobID string
	{
		store, err := sqlite.New(ctx, dbPath)
		if err != nil {
			t.Fatalf("sqlite.New: %v", err)
		}

		fr := dns.NewFakeResolver()
		fr.Hosts["restart.test"] = []net.IP{net.ParseIP(host)}
		fr.MXs["restart.test"] = []*net.MX{{Host: "mail.restart.test.", Pref: 10}}

		if err := store.Targets().Create(ctx, models.Target{ID: "t1", Value: "restart.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("create target: %v", err)
		}
		if err := store.ScopeRules().Create(ctx, models.ScopeRule{ID: "r1", Value: "restart.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("create scope rule: %v", err)
		}

		p := &Pipeline{
			Store:               store,
			Resolver:            fr,
			Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
			DefaultPorts:        []int{port},
			PortDialTimeout:     2 * time.Second,
			HTTPConfig:          httpstage.Config{Timeout: 3 * time.Second, MaxRedirects: 3},
			Concurrency:         Concurrency{DNSWorkers: 2, PortWorkers: 4, HTTPWorkers: 4},
			AllowReservedRanges: true,
			MaxCIDRHosts:        256,
			EnumerateDNSRecords: true,
			CrawlEnabled:        true,
			CrawlMaxDepth:       2,
			CrawlMaxPages:       10,
			Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
		}

		job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}})
		if err != nil {
			t.Fatalf("Run: %v (job error: %s)", err, job.Error)
		}
		if job.Status != models.ScanJobStatusCompleted {
			t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
		}
		jobID = job.ID

		// Sanity: confirm data actually exists before "restarting", so a
		// later empty result can only mean data was lost across restart,
		// not that the scan never produced anything in the first place.
		assets, _ := store.Assets().ListByScanJob(ctx, jobID)
		if len(assets) == 0 {
			t.Fatal("no assets persisted before restart -- test setup is broken")
		}

		if err := store.Close(); err != nil {
			t.Fatalf("store.Close (simulating scanner stop): %v", err)
		}
	}

	// --- Phase B: restart -- open a brand new Store against the same file. ---
	store2, err := sqlite.New(ctx, dbPath)
	if err != nil {
		t.Fatalf("sqlite.New after restart: %v", err)
	}
	defer store2.Close()

	job2, err := store2.ScanJobs().Get(ctx, jobID)
	if err != nil {
		t.Fatalf("retrieve scan job after restart: %v", err)
	}
	if job2.Status != models.ScanJobStatusCompleted {
		t.Errorf("job2.Status = %s, want completed", job2.Status)
	}
	if job2.ID != jobID {
		t.Errorf("job2.ID = %q, want %q", job2.ID, jobID)
	}

	assets, err := store2.Assets().ListByScanJob(ctx, jobID)
	if err != nil {
		t.Fatalf("Assets().ListByScanJob after restart: %v", err)
	}
	if len(assets) == 0 {
		t.Error("assets lost after restart")
	}

	hosts, err := store2.Hosts().ListByScanJob(ctx, jobID)
	if err != nil || len(hosts) == 0 {
		t.Errorf("hosts after restart: %v, %d rows", err, len(hosts))
	}

	dnsRecords, err := store2.DNSRecords().ListByScanJob(ctx, jobID)
	if err != nil || len(dnsRecords) == 0 {
		t.Errorf("dns records after restart: %v, %d rows (expected the MX record)", err, len(dnsRecords))
	}

	services, err := store2.Services().ListByScanJob(ctx, jobID)
	if err != nil || len(services) == 0 {
		t.Errorf("services after restart: %v, %d rows", err, len(services))
	}

	httpServices, err := store2.HTTPServices().ListByScanJob(ctx, jobID)
	if err != nil || len(httpServices) == 0 {
		t.Errorf("http services after restart: %v, %d rows", err, len(httpServices))
	} else if httpServices[0].Title != "Restart Test" {
		t.Errorf("http service Title = %q, want %q (field content, not just row count, must survive)", httpServices[0].Title, "Restart Test")
	}

	techs, err := store2.Technologies().ListByScanJob(ctx, jobID)
	if err != nil || len(techs) == 0 {
		t.Errorf("technologies after restart: %v, %d rows (expected nginx)", err, len(techs))
	}

	endpoints, err := store2.Endpoints().ListByScanJob(ctx, jobID)
	if err != nil || len(endpoints) == 0 {
		t.Errorf("endpoints after restart: %v, %d rows", err, len(endpoints))
	}
}
