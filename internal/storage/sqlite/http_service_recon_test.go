package sqlite

import (
	"context"
	"testing"
	"time"

	"sakanner/pkg/models"
)

func TestHTTPService_ReconFieldsRoundTrip(t *testing.T) {
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

	notAfter := now.Add(90 * 24 * time.Hour)
	httpSvc := models.HTTPService{
		ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "https://example.com/", Scheme: "https",
		StatusCode: 200,
		RedirectChain: []models.RedirectHop{
			{URL: "http://example.com/", StatusCode: 301},
			{URL: "https://www.example.com/", StatusCode: 302},
		},
		TLSSubject:    "CN=example.com",
		TLSIssuer:     "CN=Test CA",
		TLSNotAfter:   &notAfter,
		TLSVersion:    "TLS 1.3",
		TLSSelfSigned: false,
		TLSSANs:       []string{"example.com", "www.example.com", "203.0.113.5"},
		CreatedAt:     now,
	}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	got, err := s.HTTPServices().Get(ctx, "http1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if len(got.RedirectChain) != 2 {
		t.Fatalf("RedirectChain = %+v, want 2 hops", got.RedirectChain)
	}
	if got.RedirectChain[0].URL != "http://example.com/" || got.RedirectChain[0].StatusCode != 301 {
		t.Errorf("RedirectChain[0] = %+v, want {http://example.com/ 301}", got.RedirectChain[0])
	}
	if got.RedirectChain[1].URL != "https://www.example.com/" || got.RedirectChain[1].StatusCode != 302 {
		t.Errorf("RedirectChain[1] = %+v, want {https://www.example.com/ 302}", got.RedirectChain[1])
	}
	if got.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want \"TLS 1.3\"", got.TLSVersion)
	}
	if got.TLSSelfSigned {
		t.Errorf("TLSSelfSigned = true, want false")
	}
	if len(got.TLSSANs) != 3 || got.TLSSANs[2] != "203.0.113.5" {
		t.Errorf("TLSSANs = %+v, want [example.com www.example.com 203.0.113.5]", got.TLSSANs)
	}
}

func TestHTTPService_ReconFields_EmptyDefaults(t *testing.T) {
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
	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}

	// Plain HTTP (no TLS, no redirects) -- the common case; must round
	// trip cleanly with empty/zero recon fields, not error or produce
	// spurious non-nil slices.
	httpSvc := models.HTTPService{ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	got, err := s.HTTPServices().Get(ctx, "http1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.RedirectChain) != 0 {
		t.Errorf("RedirectChain = %+v, want empty", got.RedirectChain)
	}
	if got.TLSVersion != "" {
		t.Errorf("TLSVersion = %q, want empty", got.TLSVersion)
	}
	if got.TLSSelfSigned {
		t.Errorf("TLSSelfSigned = true, want false")
	}
	if len(got.TLSSANs) != 0 {
		t.Errorf("TLSSANs = %+v, want empty", got.TLSSANs)
	}
}
