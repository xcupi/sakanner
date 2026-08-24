package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

func TestDNSRecordCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "asset1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	records := []models.DNSRecord{
		{ID: "r1", ScanJobID: "job1", AssetID: "asset1", Type: models.DNSRecordTypeMX, Value: "mail.example.com", Priority: 10, CreatedAt: now},
		{ID: "r2", ScanJobID: "job1", AssetID: "asset1", Type: models.DNSRecordTypeTXT, Value: "v=spf1 -all", CreatedAt: now},
		{ID: "r3", ScanJobID: "job1", AssetID: "asset1", Type: models.DNSRecordTypeNS, Value: "ns1.example.com", CreatedAt: now},
		{ID: "r4", ScanJobID: "job1", AssetID: "asset1", Type: models.DNSRecordTypeCNAME, Value: "target.example.net", CreatedAt: now},
	}
	for _, r := range records {
		if err := s.DNSRecords().Create(ctx, r); err != nil {
			t.Fatalf("create dns record %s: %v", r.ID, err)
		}
	}

	got, err := s.DNSRecords().Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Type != models.DNSRecordTypeMX || got.Value != "mail.example.com" || got.Priority != 10 {
		t.Errorf("Get = %+v, want MX mail.example.com priority 10", got)
	}

	list, err := s.DNSRecords().ListByScanJob(ctx, "job1")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(list) != 4 {
		t.Fatalf("ListByScanJob returned %d records, want 4", len(list))
	}

	if err := s.DNSRecords().Delete(ctx, "r1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.DNSRecords().Get(ctx, "r1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

func TestDNSRecord_CascadeDeletesWithAsset(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "asset1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	record := models.DNSRecord{ID: "r1", ScanJobID: "job1", AssetID: "asset1", Type: models.DNSRecordTypeTXT, Value: "test", CreatedAt: now}
	if err := s.DNSRecords().Create(ctx, record); err != nil {
		t.Fatalf("create dns record: %v", err)
	}

	// Deleting the owning scan job (ON DELETE CASCADE through assets)
	// must remove the dns record too, keeping the DB consistent without
	// app-level cleanup code -- matches the pattern already proven for
	// assets/hosts/services/http_services/technologies.
	if err := s.ScanJobs().Delete(ctx, "job1"); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if _, err := s.DNSRecords().Get(ctx, "r1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after cascade delete: err = %v, want ErrNotFound", err)
	}
}
