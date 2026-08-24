package sqlite

import (
	"context"
	"testing"
	"time"

	"sakanner/pkg/models"
)

func TestTechnology_VersionAndSourceRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
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
	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 443, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "https://example.com/", Scheme: "https", StatusCode: 200, CreatedAt: now}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	tech := models.Technology{
		ID: "tech1", ScanJobID: "job1", HTTPServiceID: "http1",
		Name: "nginx", Version: "1.25.3", Category: "web-server", Confidence: 0.9, Source: "fingerprint",
		CreatedAt: now,
	}
	if err := s.Technologies().Create(ctx, tech); err != nil {
		t.Fatalf("create technology: %v", err)
	}

	got, err := s.Technologies().Get(ctx, "tech1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != "1.25.3" {
		t.Errorf("Version = %q, want \"1.25.3\"", got.Version)
	}
	if got.Source != "fingerprint" {
		t.Errorf("Source = %q, want \"fingerprint\"", got.Source)
	}
}
