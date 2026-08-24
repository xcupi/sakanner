package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate() call should be a no-op, got: %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestTargetCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	want := models.Target{ID: "t1", Value: "example.com", Type: models.TargetTypeDomain, Note: "primary", CreatedAt: now}
	if err := s.Targets().Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Targets().Get(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Value != want.Value || got.Type != want.Type || got.Note != want.Note {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}

	list, err := s.Targets().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d items, want 1", len(list))
	}

	if err := s.Targets().Delete(ctx, "t1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Targets().Get(ctx, "t1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

func TestScanJobCRUD_WithScopeSnapshotAndUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{
		ID:        "j1",
		TargetIDs: []string{"t1", "t2"},
		Status:    models.ScanJobStatusPending,
		ScopeSnapshot: []models.ScopeRule{
			{ID: "r1", Value: "example.com", Type: models.ScopeRuleDomainSuffix, Action: models.ScopeActionAllow, CreatedAt: now},
		},
		StartedAt: now,
		CreatedAt: now,
	}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.ScanJobs().Get(ctx, "j1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.TargetIDs) != 2 || len(got.ScopeSnapshot) != 1 {
		t.Fatalf("Get = %+v, missing target_ids or scope_snapshot", got)
	}
	if got.ScopeSnapshot[0].Value != "example.com" {
		t.Errorf("ScopeSnapshot[0].Value = %q, want example.com", got.ScopeSnapshot[0].Value)
	}
	if got.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil before completion", got.FinishedAt)
	}

	finished := now.Add(time.Minute)
	got.Status = models.ScanJobStatusCompleted
	got.FinishedAt = &finished
	if err := s.ScanJobs().Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}

	updated, err := s.ScanJobs().Get(ctx, "j1")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if updated.Status != models.ScanJobStatusCompleted {
		t.Errorf("Status = %q, want completed", updated.Status)
	}
	if updated.FinishedAt == nil || !updated.FinishedAt.Equal(finished) {
		t.Errorf("FinishedAt = %v, want %v", updated.FinishedAt, finished)
	}
}

func TestScanJobUpdate_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	err := s.ScanJobs().Update(ctx, models.ScanJob{ID: "nope", StartedAt: time.Now(), CreatedAt: time.Now()})
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Update on missing job: err = %v, want ErrNotFound", err)
	}
}

func TestWithTx_CommitsOnSuccess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	err := s.WithTx(ctx, func(tx storage.Store) error {
		return tx.Targets().Create(ctx, models.Target{ID: "tx1", Value: "a.com", Type: models.TargetTypeDomain, CreatedAt: now})
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	got, err := s.Targets().Get(ctx, "tx1")
	if err != nil {
		t.Fatalf("Get after committed tx: %v", err)
	}
	if got.Value != "a.com" {
		t.Errorf("Value = %q, want a.com", got.Value)
	}
}

func TestWithTx_RollsBackOnError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	sentinel := errors.New("boom")
	err := s.WithTx(ctx, func(tx storage.Store) error {
		if err := tx.Targets().Create(ctx, models.Target{ID: "tx2", Value: "b.com", Type: models.TargetTypeDomain, CreatedAt: now}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx: err = %v, want sentinel", err)
	}

	if _, err := s.Targets().Get(ctx, "tx2"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after rolled-back tx: err = %v, want ErrNotFound (write should not have persisted)", err)
	}
}

func TestFullPipelineFixture_CascadeAndListByScanJob(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}

	asset := models.Asset{ID: "asset1", ScanJobID: "job1", Name: "www.example.com", Source: "wordlist", CreatedAt: now}
	if err := s.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	host := models.Host{ID: "host1", ScanJobID: "job1", AssetID: "asset1", IPAddress: "203.0.113.5", CreatedAt: now}
	if err := s.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}

	svc := models.Service{ID: "svc1", ScanJobID: "job1", HostID: "host1", Port: 443, Protocol: "tcp", CreatedAt: now}
	if err := s.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}

	httpSvc := models.HTTPService{
		ID: "http1", ScanJobID: "job1", ServiceID: "svc1", URL: "https://www.example.com/", Scheme: "https",
		StatusCode: 200, Title: "Example", Headers: map[string]string{"Server": "nginx"}, CreatedAt: now,
	}
	if err := s.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	tech := models.Technology{ID: "tech1", ScanJobID: "job1", HTTPServiceID: "http1", Name: "nginx", Confidence: 0.9, CreatedAt: now}
	if err := s.Technologies().Create(ctx, tech); err != nil {
		t.Fatalf("create technology: %v", err)
	}

	assets, err := s.Assets().ListByScanJob(ctx, "job1")
	if err != nil || len(assets) != 1 {
		t.Fatalf("ListByScanJob assets: %v, len=%d", err, len(assets))
	}
	hosts, err := s.Hosts().ListByScanJob(ctx, "job1")
	if err != nil || len(hosts) != 1 {
		t.Fatalf("ListByScanJob hosts: %v, len=%d", err, len(hosts))
	}
	httpSvcs, err := s.HTTPServices().ListByScanJob(ctx, "job1")
	if err != nil || len(httpSvcs) != 1 || httpSvcs[0].Headers["Server"] != "nginx" {
		t.Fatalf("ListByScanJob http services: %v, got %+v", err, httpSvcs)
	}
	techs, err := s.Technologies().ListByScanJob(ctx, "job1")
	if err != nil || len(techs) != 1 {
		t.Fatalf("ListByScanJob technologies: %v, len=%d", err, len(techs))
	}

	// Deleting the scan job should cascade to all child rows (ON DELETE
	// CASCADE), keeping the DB consistent without app-level cleanup code.
	if err := s.ScanJobs().Delete(ctx, "job1"); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	assets, _ = s.Assets().ListByScanJob(ctx, "job1")
	if len(assets) != 0 {
		t.Errorf("expected assets to cascade-delete with scan job, got %d remaining", len(assets))
	}
	techs, _ = s.Technologies().ListByScanJob(ctx, "job1")
	if len(techs) != 0 {
		t.Errorf("expected technologies to cascade-delete with scan job, got %d remaining", len(techs))
	}
}

func TestFindingCRUD_WithEvidenceAndReferences(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job2", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}

	f := models.Finding{
		ID: "f1", ScanID: "job2", DetectorID: "reflected-xss", Target: "example.com", VulnerabilityType: "reflected-xss",
		Title: "XSS", Severity: models.SeverityHigh, Confidence: 0.8,
		Host: "example.com", Port: 443, URL: "https://example.com/search?q=x", Method: "GET",
		ValidationStatus: models.ValidationStatusUnvalidated,
		Evidence:         []models.Evidence{{ID: "e1", FindingID: "f1", Kind: models.EvidenceKindText, Content: "poc", CreatedAt: now}},
		References:       []string{"https://owasp.org/xss"},
		Source:           "sakanner",
		FirstSeen:        now, LastSeen: now,
	}
	if err := s.Findings().Create(ctx, f); err != nil {
		t.Fatalf("create finding: %v", err)
	}

	got, err := s.Findings().Get(ctx, "f1")
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Content != "poc" {
		t.Errorf("Evidence = %+v, want 1 item with content 'poc'", got.Evidence)
	}
	if len(got.References) != 1 || got.References[0] != "https://owasp.org/xss" {
		t.Errorf("References = %+v", got.References)
	}
	if got.DetectorID != "reflected-xss" || got.Host != "example.com" || got.Port != 443 || got.URL != "https://example.com/search?q=x" || got.Method != "GET" || got.Source != "sakanner" {
		t.Errorf("detector fields round-tripped incorrectly: %+v", got)
	}

	list, err := s.Findings().ListByScanJob(ctx, "job2")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByScanJob: %v, len=%d", err, len(list))
	}
}

// TestFinding_IdentityContext_RoundTripAndDefault is Phase 3.19's own
// round-trip test for the new identity_context column (migration
// 0011), mirroring the identical Endpoint/Parameter round-trip tests
// already established in Phase 3.16/3.18.
func TestFinding_IdentityContext_RoundTripAndDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job3", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}

	if err := s.Findings().Create(ctx, models.Finding{
		ID: "f-default", ScanID: "job3", DetectorID: "xss-reflected-active", VulnerabilityType: "reflected_xss",
		Severity: models.SeverityHigh, ValidationStatus: models.ValidationStatusUnvalidated, FirstSeen: now, LastSeen: now,
		// IdentityContext intentionally left unset.
	}); err != nil {
		t.Fatalf("create f-default: %v", err)
	}
	if err := s.Findings().Create(ctx, models.Finding{
		ID: "f-identity", ScanID: "job3", DetectorID: "xss-reflected-active", VulnerabilityType: "reflected_xss",
		Severity: models.SeverityHigh, ValidationStatus: models.ValidationStatusUnvalidated, IdentityContext: "account-a",
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("create f-identity: %v", err)
	}

	gotDefault, err := s.Findings().Get(ctx, "f-default")
	if err != nil {
		t.Fatalf("Get f-default: %v", err)
	}
	if gotDefault.IdentityContext != "" {
		t.Errorf("IdentityContext = %q, want empty for an unauthenticated finding", gotDefault.IdentityContext)
	}

	gotIdentity, err := s.Findings().Get(ctx, "f-identity")
	if err != nil {
		t.Fatalf("Get f-identity: %v", err)
	}
	if gotIdentity.IdentityContext != "account-a" {
		t.Errorf("IdentityContext = %q, want account-a", gotIdentity.IdentityContext)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Targets().Get(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := s.ScanJobs().Get(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := s.Findings().Get(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
