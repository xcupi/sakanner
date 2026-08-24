// Package sqlite implements sakanner's storage.Store on top of SQLite via
// the pure-Go modernc.org/sqlite driver (no cgo, so the binary builds
// natively on Ubuntu without a C toolchain).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"sakanner/internal/storage"
)

// queryer is satisfied by both *sql.DB and *sql.Tx, so repositories can be
// built against either a top-level connection or a transaction.
type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// repos implements every storage.Store repository accessor against a
// queryer, so the same code works whether it's running against the
// top-level *sql.DB or inside a WithTx transaction.
type repos struct{ q queryer }

func (r repos) Targets() storage.TargetRepository           { return targetRepo{q: r.q} }
func (r repos) ScopeRules() storage.ScopeRuleRepository     { return scopeRuleRepo{q: r.q} }
func (r repos) ScanJobs() storage.ScanJobRepository         { return scanJobRepo{q: r.q} }
func (r repos) Assets() storage.AssetRepository             { return assetRepo{q: r.q} }
func (r repos) Hosts() storage.HostRepository               { return hostRepo{q: r.q} }
func (r repos) DNSRecords() storage.DNSRecordRepository     { return dnsRecordRepo{q: r.q} }
func (r repos) Services() storage.ServiceRepository         { return serviceRepo{q: r.q} }
func (r repos) HTTPServices() storage.HTTPServiceRepository { return httpServiceRepo{q: r.q} }
func (r repos) Technologies() storage.TechnologyRepository  { return technologyRepo{q: r.q} }
func (r repos) Endpoints() storage.EndpointRepository       { return endpointRepo{q: r.q} }
func (r repos) Parameters() storage.ParameterRepository     { return parameterRepo{q: r.q} }
func (r repos) Findings() storage.FindingRepository         { return findingRepo{q: r.q} }
func (r repos) Chains() storage.ChainRepository             { return chainRepo{q: r.q} }

// store is the top-level storage.Store, backed by a real *sql.DB.
type store struct {
	repos
	db *sql.DB
}

// New opens (creating if necessary) a SQLite database at dsn and applies
// any pending migrations. dsn is a file path; ":memory:" is accepted for
// tests.
func New(ctx context.Context, dsn string) (storage.Store, error) {
	connDSN := withPragmas(dsn)

	db, err := sql.Open("sqlite", connDSN)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; avoid SQLITE_BUSY under concurrency.

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	if err := storage.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}

	if err := reconcileInterruptedJobs(ctx, db); err != nil {
		db.Close()
		return nil, err
	}

	return &store{repos: repos{q: db}, db: db}, nil
}

// reconcileInterruptedJobs runs once per New() call and marks any scan
// job left at "pending"/"running" by a process that no longer exists as
// Failed, with an explanatory error -- otherwise a scan killed via
// SIGKILL, a crash, or power loss leaves its job stuck at "running"
// forever, indistinguishable from one still genuinely in progress. A job
// whose recorded pid is still alive is left untouched (it may belong to
// a concurrent scan legitimately still running against this same
// database). This is a best-effort heuristic, not a guarantee: PIDs can
// be reused by the OS, so in the (rare, short-window) case where a dead
// scanner's pid has already been recycled by an unrelated process, the
// job is left alone rather than incorrectly reconciled.
func reconcileInterruptedJobs(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT id, pid FROM scan_jobs WHERE status IN ('pending', 'running')`)
	if err != nil {
		return fmt.Errorf("sqlite: querying interrupted jobs: %w", err)
	}
	type stale struct {
		id  string
		pid int
	}
	var toReconcile []stale
	for rows.Next() {
		var s stale
		if err := rows.Scan(&s.id, &s.pid); err != nil {
			rows.Close()
			return fmt.Errorf("sqlite: scanning interrupted job: %w", err)
		}
		if !processAlive(s.pid) {
			toReconcile = append(toReconcile, s)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterating interrupted jobs: %w", err)
	}
	rows.Close()

	for _, s := range toReconcile {
		_, err := db.ExecContext(ctx,
			`UPDATE scan_jobs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?`,
			fmt.Sprintf("interrupted: owning process (pid %d) is no longer running; detected and reconciled on startup", s.pid),
			formatTime(time.Now()), s.id)
		if err != nil {
			return fmt.Errorf("sqlite: reconciling interrupted job %s: %w", s.id, err)
		}
	}
	return nil
}

// withPragmas appends WAL mode and a busy timeout to the DSN via query
// parameters, as modernc.org/sqlite exposes pragmas through the DSN
// rather than a driver-specific Go API. ":memory:" is left untouched
// since WAL mode does not apply to in-memory databases.
func withPragmas(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pragmas := "_pragma=" + url.QueryEscape("busy_timeout(5000)") + "&_pragma=" + url.QueryEscape("foreign_keys(1)")

	// WAL mode does not apply to in-memory databases.
	if dsn != ":memory:" && !strings.HasPrefix(dsn, "file::memory:") {
		pragmas += "&_pragma=" + url.QueryEscape("journal_mode(WAL)")
	}
	return dsn + sep + pragmas
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) Migrate(ctx context.Context) error { return storage.Migrate(ctx, s.db) }

func (s *store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// WithTx runs fn against a Store bound to a single transaction, so a
// pipeline stage can persist a batch of results atomically.
func (s *store) WithTx(ctx context.Context, fn func(storage.Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin transaction: %w", err)
	}

	if err := fn(&txStore{repos: repos{q: tx}}); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("sqlite: tx failed: %w (rollback also failed: %v)", err, rbErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
}

// txStore is the storage.Store passed into WithTx's callback. Its
// lifecycle methods are unsupported -- the enclosing WithTx call owns
// commit/rollback -- and calling them is a programming error.
type txStore struct{ repos }

func (t *txStore) Close() error { return nil }

func (t *txStore) Migrate(context.Context) error {
	return errors.New("sqlite: Migrate must not be called within a transaction")
}

func (t *txStore) Ping(ctx context.Context) error {
	_, err := t.repos.q.QueryContext(ctx, "SELECT 1")
	return err
}

func (t *txStore) WithTx(context.Context, func(storage.Store) error) error {
	return errors.New("sqlite: nested transactions are not supported")
}
