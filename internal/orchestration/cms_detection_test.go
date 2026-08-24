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

// TestRun_CMSDetectionEndToEnd proves WordPress/CMS detection works
// through the REAL pipeline (fetch -> fingerprint -> persist), not just
// fingerprint.Identify() in isolation (see
// internal/fingerprint/fingerprint_test.go's TestDefaultSignatures_BodyMatches
// and TestIdentify_ExtractsVersionFromBody). Written for Phase 2
// acceptance testing, which explicitly requires evidence that a
// detected technology is actually supported by the target's response,
// not merely that the signature-matching code exists.
func TestRun_CMSDetectionEndToEnd(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><head>
			<meta name="generator" content="WordPress 6.4.2">
			<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
		</head><body>hello</body></html>`))
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
		t.Fatalf("job.Status = %s, want completed", job.Status)
	}

	techs, err := p.Store.Technologies().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	var found *models.Technology
	for i := range techs {
		if techs[i].Name == "WordPress" {
			found = &techs[i]
		}
	}
	if found == nil {
		t.Fatalf("no WordPress Technology persisted from a real fetch+fingerprint+persist run, got %+v", techs)
	}
	if found.Category != "cms" {
		t.Errorf("Category = %q, want cms", found.Category)
	}
	if found.Version != "6.4.2" {
		t.Errorf("Version = %q, want 6.4.2 (extracted from the generator meta tag actually served)", found.Version)
	}
	if found.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", found.Confidence)
	}
}
