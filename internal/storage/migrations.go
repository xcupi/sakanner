package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version  int
	name     string
	filename string
}

// loadMigrations returns embedded migrations sorted by their numeric
// prefix (e.g. 0001_init.sql -> version 1).
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("storage: reading embedded migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("storage: migration filename %q missing version prefix", e.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("storage: migration filename %q has non-numeric version prefix: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{version: version, name: e.Name(), filename: "migrations/" + e.Name()})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

// Migrate applies any embedded migrations not yet recorded in the
// database's schema_migrations table. It is safe to call on every
// startup: already-applied migrations are skipped. It fails with a
// clear error if the database's recorded schema version is newer than
// any migration this binary knows about, which guards against running
// an older binary against a newer database.
//
// The read-current-version-then-apply-pending-migrations sequence runs
// inside ONE transaction opened with "BEGIN IMMEDIATE" (issued as a
// raw statement, since database/sql's TxOptions has no portable way to
// request SQLite's IMMEDIATE mode) rather than db.BeginTx's default
// DEFERRED transaction. This closes a real check-then-act race: with a
// deferred transaction, each of several sakanner processes starting up
// concurrently against the SAME, not-yet-migrated database file reads
// "0 migrations applied" via a plain read before any of them takes a
// write lock, and all of them then race to apply migration 0001 --
// producing "table already exists"/"duplicate column" errors for every
// loser (found via Phase 3.11.1's concurrency testing: 4 of 10
// concurrent `scanner scope add` invocations against a fresh database
// failed exactly this way). BEGIN IMMEDIATE acquires SQLite's write
// lock at the START of the transaction, so a concurrent process's own
// BEGIN IMMEDIATE blocks (honoring the busy_timeout pragma already
// configured in sqlite.go's withPragmas) until the first transaction
// commits; by the time it proceeds, its own fresh read inside the now-
// active transaction correctly sees the already-migrated state and
// applies nothing further. db.SetMaxOpenConns(1) (sqlite.go) is what
// makes issuing BEGIN IMMEDIATE/COMMIT/ROLLBACK as plain ExecContext
// calls (rather than through a *sql.Tx) safe: this *sql.DB never has
// more than one physical connection, so every subsequent statement
// necessarily runs on the exact connection that holds the lock.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("storage: acquiring migration lock: %w", err)
	}
	if err := migrateLocked(ctx, db); err != nil {
		// A detached context for the rollback attempt, matching this
		// project's established "cleanup must not be skipped just
		// because the caller's own ctx is already done" pattern (see
		// internal/orchestration/pipeline.go's final-status-write
		// comment) -- though even if this rollback itself fails, the
		// caller (sqlite.New) closes the connection on any non-nil
		// error from Migrate, which discards any uncommitted
		// transaction just as effectively.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = db.ExecContext(rollbackCtx, "ROLLBACK")
		return err
	}
	if _, err := db.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("storage: committing migrations: %w", err)
	}
	return nil
}

// migrateLocked performs the actual read-then-apply work, assuming the
// caller already holds the write lock via BEGIN IMMEDIATE.
func migrateLocked(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`); err != nil {
		return fmt.Errorf("storage: creating schema_migrations table: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return nil
	}

	maxKnown := migrations[len(migrations)-1].version

	row := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	var maxApplied int
	if err := row.Scan(&maxApplied); err != nil {
		return fmt.Errorf("storage: reading current schema version: %w", err)
	}
	if maxApplied > maxKnown {
		return fmt.Errorf("storage: database schema version %d is newer than the highest migration this binary knows about (%d) -- refusing to run against a newer database", maxApplied, maxKnown)
	}

	for _, m := range migrations {
		if m.version <= maxApplied {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	sqlBytes, err := migrationFS.ReadFile(m.filename)
	if err != nil {
		return fmt.Errorf("storage: reading migration %s: %w", m.name, err)
	}
	if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("storage: applying migration %s: %w", m.name, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
		return fmt.Errorf("storage: recording migration %s: %w", m.name, err)
	}
	return nil
}
