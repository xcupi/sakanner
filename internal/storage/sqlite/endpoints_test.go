package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

func TestEndpointCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "a1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	host := models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}
	if err := s.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	endpoints := []models.Endpoint{
		{ID: "e1", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/", Method: "GET", Source: "crawl", CreatedAt: now},
		{ID: "e2", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/login", Method: "POST", Source: "form", CreatedAt: now},
		{ID: "e3", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/app.js", Method: "GET", Source: "javascript", CreatedAt: now},
	}
	for _, e := range endpoints {
		if err := s.Endpoints().Create(ctx, e); err != nil {
			t.Fatalf("create endpoint %s: %v", e.ID, err)
		}
	}

	got, err := s.Endpoints().Get(ctx, "e2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Path != "/login" || got.Method != "POST" || got.Source != "form" {
		t.Errorf("Get = %+v, want {/login POST form}", got)
	}

	list, err := s.Endpoints().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListByScanJob returned %d endpoints, want 3", len(list))
	}

	if err := s.Endpoints().Delete(ctx, "e1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Endpoints().Get(ctx, "e1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

// TestEndpoint_ActionOrigin_RoundTrip is Phase 3.21's own round-trip
// test for the new action_origin column (migration 0012), mirroring
// TestEndpoint_APIFields_RoundTrip's exact structure.
func TestEndpoint_ActionOrigin_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "a1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	host := models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}
	if err := s.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	if err := s.Endpoints().Create(ctx, models.Endpoint{
		ID: "e-crawl", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/", Method: "GET", Source: "crawl", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint e-crawl: %v", err)
	}
	if err := s.Endpoints().Create(ctx, models.Endpoint{
		ID: "e-form", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/steal", Method: "POST", Source: "form",
		ActionOrigin: "http://external.scanner.test:80", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint e-form: %v", err)
	}

	gotForm, err := s.Endpoints().Get(ctx, "e-form")
	if err != nil {
		t.Fatalf("Get e-form: %v", err)
	}
	if gotForm.ActionOrigin != "http://external.scanner.test:80" {
		t.Errorf("ActionOrigin = %q, want http://external.scanner.test:80", gotForm.ActionOrigin)
	}

	// The crawl-sourced endpoint never set ActionOrigin -- must read
	// back as the zero value (""), preserving pre-Phase-3.21 behavior
	// exactly.
	gotCrawl, err := s.Endpoints().Get(ctx, "e-crawl")
	if err != nil {
		t.Fatalf("Get e-crawl: %v", err)
	}
	if gotCrawl.ActionOrigin != "" {
		t.Errorf("e-crawl.ActionOrigin = %q, want empty", gotCrawl.ActionOrigin)
	}

	list, err := s.Endpoints().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	byID := map[string]models.Endpoint{}
	for _, e := range list {
		byID[e.ID] = e
	}
	if byID["e-form"].ActionOrigin != "http://external.scanner.test:80" || byID["e-crawl"].ActionOrigin != "" {
		t.Errorf("ListByScanJob did not preserve ActionOrigin: %+v", byID)
	}
}

func TestEndpoint_CascadeDeletesWithHTTPService(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "a1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	host := models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}
	if err := s.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	endpoint := models.Endpoint{ID: "e1", ScanJobID: "job1", HTTPServiceID: "http1", Path: "/", Method: "GET", Source: "crawl", CreatedAt: now}
	if err := s.Endpoints().Create(ctx, endpoint); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	if err := s.ScanJobs().Delete(ctx, "job1"); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if _, err := s.Endpoints().Get(ctx, "e1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after cascade delete: err = %v, want ErrNotFound", err)
	}
}
