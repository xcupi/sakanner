package sqlite

import (
	"context"
	"database/sql"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// TestReconcileInterruptedJobs_DeadPIDIsReconciled simulates a scan job
// left "running" by a process that has since exited (the SIGKILL/crash
// scenario) by writing a row with a pid that we know is dead, then
// opening a fresh Store and confirming it's reconciled to Failed.
func TestReconcileInterruptedJobs_DeadPIDIsReconciled(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	ctx := context.Background()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now().UTC()
	job := models.ScanJob{ID: "orphan1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	s.Close()

	// Overwrite the pid with a value that's certain to be dead: spawn a
	// short-lived process, wait for it to exit, and reuse its pid. Using
	// an actually-terminated pid (rather than a made-up huge number) is
	// more realistic than guessing, and avoids the (unlikely but
	// possible) case of accidentally colliding with this test process
	// itself or another real running process.
	deadPID := spawnAndWaitForDeadPID(t)

	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := rawDB.Exec(`UPDATE scan_jobs SET pid = ? WHERE id = ?`, deadPID, "orphan1"); err != nil {
		t.Fatalf("set pid: %v", err)
	}
	rawDB.Close()

	// Re-opening the store (simulating a fresh process starting up)
	// must reconcile the orphaned job.
	s2, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New (second open): %v", err)
	}
	defer s2.Close()

	got, err := s2.ScanJobs().Get(ctx, "orphan1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != models.ScanJobStatusFailed {
		t.Errorf("Status = %s, want failed (job with a dead pid must be reconciled)", got.Status)
	}
	if got.Error == "" {
		t.Error("expected a non-empty explanatory error on the reconciled job")
	}
	if got.FinishedAt == nil {
		t.Error("expected FinishedAt to be set on the reconciled job")
	}
}

// TestReconcileInterruptedJobs_LivePIDIsUntouched proves a job whose
// recorded pid is the CURRENT process (definitely alive) is left alone
// -- this is the case of a legitimately still-running concurrent scan
// against the same database.
func TestReconcileInterruptedJobs_LivePIDIsUntouched(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	ctx := context.Background()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now().UTC()
	job := models.ScanJob{ID: "live1", Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}
	if err := s.ScanJobs().Create(ctx, job); err != nil { // Create() records os.Getpid(), which is alive by definition
		t.Fatalf("create job: %v", err)
	}
	s.Close()

	s2, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("New (second open): %v", err)
	}
	defer s2.Close()

	got, err := s2.ScanJobs().Get(ctx, "live1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != models.ScanJobStatusRunning {
		t.Errorf("Status = %s, want running (job owned by this still-alive process must not be reconciled)", got.Status)
	}
}

func spawnAndWaitForDeadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn helper process: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for helper process: %v", err)
	}
	if processAlive(pid) {
		t.Skipf("pid %d unexpectedly still appears alive (reaped/reused too fast); skipping", pid)
	}
	return pid
}
