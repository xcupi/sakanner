package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"sakanner/internal/chains"
	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

const timeLayout = time.RFC3339Nano

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) { return time.Parse(timeLayout, s) }

func formatTimePtr(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(*t), Valid: true}
}

func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func marshalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- targets ----

type targetRepo struct{ q queryer }

func (r targetRepo) Create(ctx context.Context, t models.Target) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO targets (id, value, type, note, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Value, string(t.Type), t.Note, formatTime(t.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create target: %w", err)
	}
	return nil
}

func (r targetRepo) Get(ctx context.Context, id string) (models.Target, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, value, type, note, created_at FROM targets WHERE id = ?`, id)
	return scanTarget(row)
}

func (r targetRepo) List(ctx context.Context) ([]models.Target, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, value, type, note, created_at FROM targets ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list targets: %w", err)
	}
	defer rows.Close()

	out := []models.Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r targetRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete target: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTarget(row rowScanner) (models.Target, error) {
	var t models.Target
	var typ, createdAt string
	if err := row.Scan(&t.ID, &t.Value, &typ, &t.Note, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Target{}, storage.ErrNotFound
		}
		return models.Target{}, fmt.Errorf("sqlite: scan target: %w", err)
	}
	t.Type = models.TargetType(typ)
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Target{}, fmt.Errorf("sqlite: parse target created_at: %w", err)
	}
	t.CreatedAt = ts
	return t, nil
}

// ---- scope rules ----

type scopeRuleRepo struct{ q queryer }

func (r scopeRuleRepo) Create(ctx context.Context, sr models.ScopeRule) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO scope_rules (id, value, type, action, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		sr.ID, sr.Value, string(sr.Type), string(sr.Action), sr.Note, formatTime(sr.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create scope rule: %w", err)
	}
	return nil
}

func (r scopeRuleRepo) Get(ctx context.Context, id string) (models.ScopeRule, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, value, type, action, note, created_at FROM scope_rules WHERE id = ?`, id)
	return scanScopeRule(row)
}

func (r scopeRuleRepo) List(ctx context.Context) ([]models.ScopeRule, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, value, type, action, note, created_at FROM scope_rules ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list scope rules: %w", err)
	}
	defer rows.Close()

	out := []models.ScopeRule{}
	for rows.Next() {
		sr, err := scanScopeRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sr)
	}
	return out, rows.Err()
}

func (r scopeRuleRepo) Delete(ctx context.Context, id string) error {
	res, err := r.q.ExecContext(ctx, `DELETE FROM scope_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete scope rule: %w", err)
	}
	return checkRowsAffected(res, "scope rule")
}

func scanScopeRule(row rowScanner) (models.ScopeRule, error) {
	var sr models.ScopeRule
	var typ, action, createdAt string
	if err := row.Scan(&sr.ID, &sr.Value, &typ, &action, &sr.Note, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.ScopeRule{}, storage.ErrNotFound
		}
		return models.ScopeRule{}, fmt.Errorf("sqlite: scan scope rule: %w", err)
	}
	sr.Type = models.ScopeRuleType(typ)
	sr.Action = models.ScopeAction(action)
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.ScopeRule{}, fmt.Errorf("sqlite: parse scope rule created_at: %w", err)
	}
	sr.CreatedAt = ts
	return sr, nil
}

// ---- scan jobs ----

type scanJobRepo struct{ q queryer }

func (r scanJobRepo) Create(ctx context.Context, j models.ScanJob) error {
	targetIDs, err := marshalJSON(j.TargetIDs)
	if err != nil {
		return fmt.Errorf("sqlite: marshal target_ids: %w", err)
	}
	scopeSnapshot, err := marshalJSON(j.ScopeSnapshot)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scope_snapshot: %w", err)
	}
	// pid records the OS process that owns this job, purely as a
	// storage-layer implementation detail (not part of the domain
	// model) used to detect and reconcile jobs orphaned by a process
	// that was killed (SIGKILL, crash, power loss) rather than shut down
	// gracefully -- see reconcileInterruptedJobs in sqlite.go.
	_, err = r.q.ExecContext(ctx,
		`INSERT INTO scan_jobs (id, target_ids, status, error, scope_snapshot, config, started_at, finished_at, created_at, pid)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, targetIDs, string(j.Status), j.Error, scopeSnapshot, j.Config,
		formatTime(j.StartedAt), formatTimePtr(j.FinishedAt), formatTime(j.CreatedAt), os.Getpid())
	if err != nil {
		return fmt.Errorf("sqlite: create scan job: %w", err)
	}
	return nil
}

func (r scanJobRepo) Get(ctx context.Context, id string) (models.ScanJob, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT id, target_ids, status, error, scope_snapshot, config, started_at, finished_at, created_at
		 FROM scan_jobs WHERE id = ?`, id)
	return scanScanJob(row)
}

func (r scanJobRepo) List(ctx context.Context) ([]models.ScanJob, error) {
	rows, err := r.q.QueryContext(ctx,
		`SELECT id, target_ids, status, error, scope_snapshot, config, started_at, finished_at, created_at
		 FROM scan_jobs ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list scan jobs: %w", err)
	}
	defer rows.Close()

	out := []models.ScanJob{}
	for rows.Next() {
		j, err := scanScanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (r scanJobRepo) Update(ctx context.Context, j models.ScanJob) error {
	targetIDs, err := marshalJSON(j.TargetIDs)
	if err != nil {
		return fmt.Errorf("sqlite: marshal target_ids: %w", err)
	}
	scopeSnapshot, err := marshalJSON(j.ScopeSnapshot)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scope_snapshot: %w", err)
	}
	res, err := r.q.ExecContext(ctx,
		`UPDATE scan_jobs SET target_ids = ?, status = ?, error = ?, scope_snapshot = ?, config = ?, started_at = ?, finished_at = ?
		 WHERE id = ?`,
		targetIDs, string(j.Status), j.Error, scopeSnapshot, j.Config,
		formatTime(j.StartedAt), formatTimePtr(j.FinishedAt), j.ID)
	if err != nil {
		return fmt.Errorf("sqlite: update scan job: %w", err)
	}
	return checkRowsAffected(res, "scan job")
}

func (r scanJobRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM scan_jobs WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete scan job: %w", err)
	}
	return nil
}

func scanScanJob(row rowScanner) (models.ScanJob, error) {
	var j models.ScanJob
	var targetIDs, status, scopeSnapshot, startedAt, createdAt string
	var finishedAt sql.NullString
	if err := row.Scan(&j.ID, &targetIDs, &status, &j.Error, &scopeSnapshot, &j.Config, &startedAt, &finishedAt, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.ScanJob{}, storage.ErrNotFound
		}
		return models.ScanJob{}, fmt.Errorf("sqlite: scan scan job: %w", err)
	}
	j.Status = models.ScanJobStatus(status)
	if err := json.Unmarshal([]byte(targetIDs), &j.TargetIDs); err != nil {
		return models.ScanJob{}, fmt.Errorf("sqlite: unmarshal target_ids: %w", err)
	}
	if err := json.Unmarshal([]byte(scopeSnapshot), &j.ScopeSnapshot); err != nil {
		return models.ScanJob{}, fmt.Errorf("sqlite: unmarshal scope_snapshot: %w", err)
	}
	ts, err := parseTime(startedAt)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("sqlite: parse started_at: %w", err)
	}
	j.StartedAt = ts
	if j.FinishedAt, err = parseTimePtr(finishedAt); err != nil {
		return models.ScanJob{}, fmt.Errorf("sqlite: parse finished_at: %w", err)
	}
	cts, err := parseTime(createdAt)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("sqlite: parse created_at: %w", err)
	}
	j.CreatedAt = cts
	return j, nil
}

func checkRowsAffected(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: rows affected for %s: %w", what, err)
	}
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---- assets ----

type assetRepo struct{ q queryer }

func (r assetRepo) Create(ctx context.Context, a models.Asset) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO assets (id, scan_job_id, name, source, created_at) VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.ScanJobID, a.Name, a.Source, formatTime(a.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create asset: %w", err)
	}
	return nil
}

func (r assetRepo) Get(ctx context.Context, id string) (models.Asset, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, scan_job_id, name, source, created_at FROM assets WHERE id = ?`, id)
	return scanAsset(row)
}

func (r assetRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Asset, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, scan_job_id, name, source, created_at FROM assets WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list assets: %w", err)
	}
	defer rows.Close()

	out := []models.Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r assetRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete asset: %w", err)
	}
	return nil
}

func scanAsset(row rowScanner) (models.Asset, error) {
	var a models.Asset
	var createdAt string
	if err := row.Scan(&a.ID, &a.ScanJobID, &a.Name, &a.Source, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Asset{}, storage.ErrNotFound
		}
		return models.Asset{}, fmt.Errorf("sqlite: scan asset: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Asset{}, fmt.Errorf("sqlite: parse asset created_at: %w", err)
	}
	a.CreatedAt = ts
	return a, nil
}

// ---- hosts ----

type hostRepo struct{ q queryer }

func (r hostRepo) Create(ctx context.Context, h models.Host) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO hosts (id, scan_job_id, asset_id, ip_address, created_at) VALUES (?, ?, ?, ?, ?)`,
		h.ID, h.ScanJobID, h.AssetID, h.IPAddress, formatTime(h.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create host: %w", err)
	}
	return nil
}

func (r hostRepo) Get(ctx context.Context, id string) (models.Host, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, scan_job_id, asset_id, ip_address, created_at FROM hosts WHERE id = ?`, id)
	return scanHost(row)
}

func (r hostRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Host, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, scan_job_id, asset_id, ip_address, created_at FROM hosts WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list hosts: %w", err)
	}
	defer rows.Close()

	out := []models.Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (r hostRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete host: %w", err)
	}
	return nil
}

func scanHost(row rowScanner) (models.Host, error) {
	var h models.Host
	var createdAt string
	if err := row.Scan(&h.ID, &h.ScanJobID, &h.AssetID, &h.IPAddress, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Host{}, storage.ErrNotFound
		}
		return models.Host{}, fmt.Errorf("sqlite: scan host: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Host{}, fmt.Errorf("sqlite: parse host created_at: %w", err)
	}
	h.CreatedAt = ts
	return h, nil
}

// ---- dns records ----

type dnsRecordRepo struct{ q queryer }

func (r dnsRecordRepo) Create(ctx context.Context, dr models.DNSRecord) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO dns_records (id, scan_job_id, asset_id, type, value, priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		dr.ID, dr.ScanJobID, dr.AssetID, string(dr.Type), dr.Value, dr.Priority, formatTime(dr.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create dns record: %w", err)
	}
	return nil
}

func (r dnsRecordRepo) Get(ctx context.Context, id string) (models.DNSRecord, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, scan_job_id, asset_id, type, value, priority, created_at FROM dns_records WHERE id = ?`, id)
	return scanDNSRecord(row)
}

func (r dnsRecordRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.DNSRecord, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, scan_job_id, asset_id, type, value, priority, created_at FROM dns_records WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list dns records: %w", err)
	}
	defer rows.Close()

	out := []models.DNSRecord{}
	for rows.Next() {
		dr, err := scanDNSRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dr)
	}
	return out, rows.Err()
}

func (r dnsRecordRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM dns_records WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete dns record: %w", err)
	}
	return nil
}

func scanDNSRecord(row rowScanner) (models.DNSRecord, error) {
	var dr models.DNSRecord
	var typ, createdAt string
	if err := row.Scan(&dr.ID, &dr.ScanJobID, &dr.AssetID, &typ, &dr.Value, &dr.Priority, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.DNSRecord{}, storage.ErrNotFound
		}
		return models.DNSRecord{}, fmt.Errorf("sqlite: scan dns record: %w", err)
	}
	dr.Type = models.DNSRecordType(typ)
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.DNSRecord{}, fmt.Errorf("sqlite: parse dns record created_at: %w", err)
	}
	dr.CreatedAt = ts
	return dr, nil
}

// ---- services ----

type serviceRepo struct{ q queryer }

func (r serviceRepo) Create(ctx context.Context, s models.Service) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO services (id, scan_job_id, host_id, port, protocol, banner, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.ScanJobID, s.HostID, s.Port, s.Protocol, s.Banner, formatTime(s.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create service: %w", err)
	}
	return nil
}

func (r serviceRepo) Get(ctx context.Context, id string) (models.Service, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, scan_job_id, host_id, port, protocol, banner, created_at FROM services WHERE id = ?`, id)
	return scanService(row)
}

func (r serviceRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Service, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, scan_job_id, host_id, port, protocol, banner, created_at FROM services WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list services: %w", err)
	}
	defer rows.Close()

	out := []models.Service{}
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r serviceRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM services WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete service: %w", err)
	}
	return nil
}

func scanService(row rowScanner) (models.Service, error) {
	var s models.Service
	var createdAt string
	if err := row.Scan(&s.ID, &s.ScanJobID, &s.HostID, &s.Port, &s.Protocol, &s.Banner, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Service{}, storage.ErrNotFound
		}
		return models.Service{}, fmt.Errorf("sqlite: scan service: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Service{}, fmt.Errorf("sqlite: parse service created_at: %w", err)
	}
	s.CreatedAt = ts
	return s, nil
}

// ---- http services ----

type httpServiceRepo struct{ q queryer }

func (r httpServiceRepo) Create(ctx context.Context, h models.HTTPService) error {
	headers, err := marshalJSON(h.Headers)
	if err != nil {
		return fmt.Errorf("sqlite: marshal headers: %w", err)
	}
	redirectChain, err := marshalJSON(h.RedirectChain)
	if err != nil {
		return fmt.Errorf("sqlite: marshal redirect_chain: %w", err)
	}
	tlsSANs, err := marshalJSON(h.TLSSANs)
	if err != nil {
		return fmt.Errorf("sqlite: marshal tls_sans: %w", err)
	}
	_, err = r.q.ExecContext(ctx,
		`INSERT INTO http_services (id, scan_job_id, service_id, url, scheme, status_code, title, headers, redirect_chain, tls_subject, tls_issuer, tls_not_after, tls_version, tls_self_signed, tls_sans, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.ScanJobID, h.ServiceID, h.URL, h.Scheme, h.StatusCode, h.Title, headers, redirectChain,
		h.TLSSubject, h.TLSIssuer, formatTimePtr(h.TLSNotAfter), h.TLSVersion, h.TLSSelfSigned, tlsSANs, formatTime(h.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create http service: %w", err)
	}
	return nil
}

const httpServiceSelect = `SELECT id, scan_job_id, service_id, url, scheme, status_code, title, headers, redirect_chain, tls_subject, tls_issuer, tls_not_after, tls_version, tls_self_signed, tls_sans, created_at FROM http_services`

func (r httpServiceRepo) Get(ctx context.Context, id string) (models.HTTPService, error) {
	row := r.q.QueryRowContext(ctx, httpServiceSelect+` WHERE id = ?`, id)
	return scanHTTPService(row)
}

func (r httpServiceRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.HTTPService, error) {
	rows, err := r.q.QueryContext(ctx, httpServiceSelect+` WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list http services: %w", err)
	}
	defer rows.Close()

	out := []models.HTTPService{}
	for rows.Next() {
		h, err := scanHTTPService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (r httpServiceRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM http_services WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete http service: %w", err)
	}
	return nil
}

func scanHTTPService(row rowScanner) (models.HTTPService, error) {
	var h models.HTTPService
	var headers, redirectChain, tlsSANs, createdAt string
	var tlsNotAfter sql.NullString
	if err := row.Scan(&h.ID, &h.ScanJobID, &h.ServiceID, &h.URL, &h.Scheme, &h.StatusCode, &h.Title, &headers, &redirectChain,
		&h.TLSSubject, &h.TLSIssuer, &tlsNotAfter, &h.TLSVersion, &h.TLSSelfSigned, &tlsSANs, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.HTTPService{}, storage.ErrNotFound
		}
		return models.HTTPService{}, fmt.Errorf("sqlite: scan http service: %w", err)
	}
	if headers != "" {
		if err := json.Unmarshal([]byte(headers), &h.Headers); err != nil {
			return models.HTTPService{}, fmt.Errorf("sqlite: unmarshal headers: %w", err)
		}
	}
	if redirectChain != "" {
		if err := json.Unmarshal([]byte(redirectChain), &h.RedirectChain); err != nil {
			return models.HTTPService{}, fmt.Errorf("sqlite: unmarshal redirect_chain: %w", err)
		}
	}
	if tlsSANs != "" {
		if err := json.Unmarshal([]byte(tlsSANs), &h.TLSSANs); err != nil {
			return models.HTTPService{}, fmt.Errorf("sqlite: unmarshal tls_sans: %w", err)
		}
	}
	var err error
	if h.TLSNotAfter, err = parseTimePtr(tlsNotAfter); err != nil {
		return models.HTTPService{}, fmt.Errorf("sqlite: parse tls_not_after: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.HTTPService{}, fmt.Errorf("sqlite: parse http service created_at: %w", err)
	}
	h.CreatedAt = ts
	return h, nil
}

// ---- technologies ----

type technologyRepo struct{ q queryer }

func (r technologyRepo) Create(ctx context.Context, t models.Technology) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO technologies (id, scan_job_id, http_service_id, name, version, category, confidence, source, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ScanJobID, t.HTTPServiceID, t.Name, t.Version, t.Category, t.Confidence, t.Source, formatTime(t.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create technology: %w", err)
	}
	return nil
}

const technologySelect = `SELECT id, scan_job_id, http_service_id, name, version, category, confidence, source, created_at FROM technologies`

func (r technologyRepo) Get(ctx context.Context, id string) (models.Technology, error) {
	row := r.q.QueryRowContext(ctx, technologySelect+` WHERE id = ?`, id)
	return scanTechnology(row)
}

func (r technologyRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Technology, error) {
	rows, err := r.q.QueryContext(ctx, technologySelect+` WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list technologies: %w", err)
	}
	defer rows.Close()

	out := []models.Technology{}
	for rows.Next() {
		t, err := scanTechnology(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r technologyRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM technologies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete technology: %w", err)
	}
	return nil
}

func scanTechnology(row rowScanner) (models.Technology, error) {
	var t models.Technology
	var createdAt string
	if err := row.Scan(&t.ID, &t.ScanJobID, &t.HTTPServiceID, &t.Name, &t.Version, &t.Category, &t.Confidence, &t.Source, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Technology{}, storage.ErrNotFound
		}
		return models.Technology{}, fmt.Errorf("sqlite: scan technology: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Technology{}, fmt.Errorf("sqlite: parse technology created_at: %w", err)
	}
	t.CreatedAt = ts
	return t, nil
}

// ---- endpoints ----

type endpointRepo struct{ q queryer }

func (r endpointRepo) Create(ctx context.Context, e models.Endpoint) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO endpoints (id, scan_job_id, http_service_id, path, method, source, identity_context, api_candidate, api_evidence, response_content_type, action_origin, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.ScanJobID, e.HTTPServiceID, e.Path, e.Method, e.Source, e.IdentityContext, e.APICandidate, e.APIEvidence, e.ResponseContentType, e.ActionOrigin, formatTime(e.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create endpoint: %w", err)
	}
	return nil
}

func (r endpointRepo) Get(ctx context.Context, id string) (models.Endpoint, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, scan_job_id, http_service_id, path, method, source, identity_context, api_candidate, api_evidence, response_content_type, action_origin, created_at FROM endpoints WHERE id = ?`, id)
	return scanEndpoint(row)
}

func (r endpointRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Endpoint, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, scan_job_id, http_service_id, path, method, source, identity_context, api_candidate, api_evidence, response_content_type, action_origin, created_at FROM endpoints WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list endpoints: %w", err)
	}
	defer rows.Close()

	out := []models.Endpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r endpointRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM endpoints WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete endpoint: %w", err)
	}
	return nil
}

func scanEndpoint(row rowScanner) (models.Endpoint, error) {
	var e models.Endpoint
	var createdAt string
	if err := row.Scan(&e.ID, &e.ScanJobID, &e.HTTPServiceID, &e.Path, &e.Method, &e.Source, &e.IdentityContext, &e.APICandidate, &e.APIEvidence, &e.ResponseContentType, &e.ActionOrigin, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Endpoint{}, storage.ErrNotFound
		}
		return models.Endpoint{}, fmt.Errorf("sqlite: scan endpoint: %w", err)
	}
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Endpoint{}, fmt.Errorf("sqlite: parse endpoint created_at: %w", err)
	}
	e.CreatedAt = ts
	return e, nil
}

// ---- parameters ----

type parameterRepo struct{ q queryer }

func (r parameterRepo) Create(ctx context.Context, p models.Parameter) error {
	provenance := p.Provenance
	if provenance == "" {
		provenance = "REQUEST_INPUT"
	}
	// PathSegmentIndex is only ever meaningful for Location == "path"
	// (see models.Parameter's own doc comment) -- forced to -1 for
	// every other Location, REGARDLESS of what the caller's struct
	// literal happened to leave in the field, so no call site
	// (existing or future) needs to remember to set this explicitly
	// for a non-path Parameter. Mirrors this function's own existing
	// Provenance-defaulting discipline immediately above.
	pathSegmentIndex := p.PathSegmentIndex
	if p.Location != "path" {
		pathSegmentIndex = -1
	}
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO parameters (id, scan_job_id, endpoint_id, name, location, classification, method, value, source, content_type, required, evidence_ref, identity_context, provenance, hidden, path_segment_index, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ScanJobID, p.EndpointID, p.Name, p.Location, p.Classification, p.Method, p.Value, p.Source, p.ContentType,
		nullBoolFromPtr(p.Required), p.EvidenceRef, p.IdentityContext, provenance, p.Hidden, pathSegmentIndex, formatTime(p.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create parameter: %w", err)
	}
	return nil
}

func (r parameterRepo) Get(ctx context.Context, id string) (models.Parameter, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT id, scan_job_id, endpoint_id, name, location, classification, method, value, source, content_type, required, evidence_ref, identity_context, provenance, hidden, path_segment_index, created_at
		 FROM parameters WHERE id = ?`, id)
	return scanParameter(row)
}

func (r parameterRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Parameter, error) {
	rows, err := r.q.QueryContext(ctx,
		`SELECT id, scan_job_id, endpoint_id, name, location, classification, method, value, source, content_type, required, evidence_ref, identity_context, provenance, hidden, path_segment_index, created_at
		 FROM parameters WHERE scan_job_id = ? ORDER BY created_at`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list parameters: %w", err)
	}
	defer rows.Close()

	out := []models.Parameter{}
	for rows.Next() {
		p, err := scanParameter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r parameterRepo) Delete(ctx context.Context, id string) error {
	res, err := r.q.ExecContext(ctx, `DELETE FROM parameters WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete parameter: %w", err)
	}
	return checkRowsAffected(res, "parameter")
}

func scanParameter(row rowScanner) (models.Parameter, error) {
	var p models.Parameter
	var required sql.NullBool
	var createdAt string
	if err := row.Scan(&p.ID, &p.ScanJobID, &p.EndpointID, &p.Name, &p.Location, &p.Classification, &p.Method, &p.Value,
		&p.Source, &p.ContentType, &required, &p.EvidenceRef, &p.IdentityContext, &p.Provenance, &p.Hidden, &p.PathSegmentIndex, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return models.Parameter{}, storage.ErrNotFound
		}
		return models.Parameter{}, fmt.Errorf("sqlite: scan parameter: %w", err)
	}
	p.Required = ptrFromNullBool(required)
	ts, err := parseTime(createdAt)
	if err != nil {
		return models.Parameter{}, fmt.Errorf("sqlite: parse parameter created_at: %w", err)
	}
	p.CreatedAt = ts
	return p, nil
}

func nullBoolFromPtr(b *bool) sql.NullBool {
	if b == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *b, Valid: true}
}

func ptrFromNullBool(nb sql.NullBool) *bool {
	if !nb.Valid {
		return nil
	}
	b := nb.Bool
	return &b
}

// ---- findings ----

type findingRepo struct{ q queryer }

func (r findingRepo) Create(ctx context.Context, f models.Finding) error {
	evidence, err := marshalJSON(f.Evidence)
	if err != nil {
		return fmt.Errorf("sqlite: marshal evidence: %w", err)
	}
	references, err := marshalJSON(f.References)
	if err != nil {
		return fmt.Errorf("sqlite: marshal references: %w", err)
	}
	_, err = r.q.ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, detector_id, target, asset, vulnerability_type, title, description, severity, confidence,
		 host, port, url, method, affected_endpoint, affected_parameter, detection_method, validation_status, evidence, remediation, "references",
		 source, identity_context, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ScanID, f.DetectorID, f.Target, f.Asset, f.VulnerabilityType, f.Title, f.Description, string(f.Severity), f.Confidence,
		f.Host, f.Port, f.URL, f.Method, f.AffectedEndpoint, f.AffectedParameter, f.DetectionMethod, string(f.ValidationStatus), evidence, f.Remediation, references,
		f.Source, f.IdentityContext, formatTime(f.FirstSeen), formatTime(f.LastSeen))
	if err != nil {
		return fmt.Errorf("sqlite: create finding: %w", err)
	}
	return nil
}

func (r findingRepo) Get(ctx context.Context, id string) (models.Finding, error) {
	row := r.q.QueryRowContext(ctx, findingSelect+` WHERE id = ?`, id)
	return scanFinding(row)
}

func (r findingRepo) ListByScanJob(ctx context.Context, scanJobID string) ([]models.Finding, error) {
	rows, err := r.q.QueryContext(ctx, findingSelect+` WHERE scan_id = ? ORDER BY first_seen`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list findings: %w", err)
	}
	defer rows.Close()

	out := []models.Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r findingRepo) Delete(ctx context.Context, id string) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM findings WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete finding: %w", err)
	}
	return nil
}

const findingSelect = `SELECT id, scan_id, detector_id, target, asset, vulnerability_type, title, description, severity, confidence,
	 host, port, url, method, affected_endpoint, affected_parameter, detection_method, validation_status, evidence, remediation, "references",
	 source, identity_context, first_seen, last_seen FROM findings`

func scanFinding(row rowScanner) (models.Finding, error) {
	var f models.Finding
	var severity, validationStatus, evidence, references, firstSeen, lastSeen string
	if err := row.Scan(&f.ID, &f.ScanID, &f.DetectorID, &f.Target, &f.Asset, &f.VulnerabilityType, &f.Title, &f.Description, &severity, &f.Confidence,
		&f.Host, &f.Port, &f.URL, &f.Method, &f.AffectedEndpoint, &f.AffectedParameter, &f.DetectionMethod, &validationStatus, &evidence, &f.Remediation, &references,
		&f.Source, &f.IdentityContext, &firstSeen, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return models.Finding{}, storage.ErrNotFound
		}
		return models.Finding{}, fmt.Errorf("sqlite: scan finding: %w", err)
	}
	f.Severity = models.Severity(severity)
	f.ValidationStatus = models.ValidationStatus(validationStatus)
	if evidence != "" {
		if err := json.Unmarshal([]byte(evidence), &f.Evidence); err != nil {
			return models.Finding{}, fmt.Errorf("sqlite: unmarshal evidence: %w", err)
		}
	}
	if references != "" {
		if err := json.Unmarshal([]byte(references), &f.References); err != nil {
			return models.Finding{}, fmt.Errorf("sqlite: unmarshal references: %w", err)
		}
	}
	ts, err := parseTime(firstSeen)
	if err != nil {
		return models.Finding{}, fmt.Errorf("sqlite: parse first_seen: %w", err)
	}
	f.FirstSeen = ts
	ts, err = parseTime(lastSeen)
	if err != nil {
		return models.Finding{}, fmt.Errorf("sqlite: parse last_seen: %w", err)
	}
	f.LastSeen = ts
	return f, nil
}

// ---- chains (Phase 3.31) ----

type chainRepo struct{ q queryer }

// SaveResult replaces (DELETE then INSERT, never append) any
// previously saved relations/candidates for scanJobID -- see
// storage.ChainRepository's own doc comment for why this makes
// re-saving always safe and always deterministic.
func (r chainRepo) SaveResult(ctx context.Context, scanJobID string, result chains.Result) error {
	if _, err := r.q.ExecContext(ctx, `DELETE FROM chain_relations WHERE scan_job_id = ?`, scanJobID); err != nil {
		return fmt.Errorf("sqlite: delete existing chain relations: %w", err)
	}
	if _, err := r.q.ExecContext(ctx, `DELETE FROM chain_candidates WHERE scan_job_id = ?`, scanJobID); err != nil {
		return fmt.Errorf("sqlite: delete existing chain candidates: %w", err)
	}

	now := formatTime(time.Now().UTC())
	for _, rel := range result.Relations {
		evidence, err := marshalJSON(rel.Evidence)
		if err != nil {
			return fmt.Errorf("sqlite: marshal relation evidence: %w", err)
		}
		_, err = r.q.ExecContext(ctx,
			`INSERT INTO chain_relations (id, scan_job_id, relation_type, finding_a_id, finding_b_id, reason, evidence, confidence, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rel.ID, scanJobID, string(rel.Type), rel.FindingAID, rel.FindingBID, rel.Reason, evidence, rel.Confidence, now)
		if err != nil {
			return fmt.Errorf("sqlite: create chain relation: %w", err)
		}
	}

	for _, c := range result.Candidates {
		findingIDs, err := marshalJSON(c.FindingIDs)
		if err != nil {
			return fmt.Errorf("sqlite: marshal candidate finding ids: %w", err)
		}
		relationIDs, err := marshalJSON(c.RelationIDs)
		if err != nil {
			return fmt.Errorf("sqlite: marshal candidate relation ids: %w", err)
		}
		endpoints, err := marshalJSON(c.Endpoints)
		if err != nil {
			return fmt.Errorf("sqlite: marshal candidate endpoints: %w", err)
		}
		missing, err := marshalJSON(c.MissingEvidence)
		if err != nil {
			return fmt.Errorf("sqlite: marshal candidate missing evidence: %w", err)
		}
		_, err = r.q.ExecContext(ctx,
			`INSERT INTO chain_candidates (id, scan_job_id, identity_context, finding_ids, relation_ids, endpoints, status, confidence, impact_estimate, reason, missing_evidence, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, scanJobID, c.IdentityContext, findingIDs, relationIDs, endpoints, string(c.Status), c.Confidence, c.ImpactEstimate, c.Reason, missing, now)
		if err != nil {
			return fmt.Errorf("sqlite: create chain candidate: %w", err)
		}
	}
	return nil
}

const chainRelationSelect = `SELECT id, scan_job_id, relation_type, finding_a_id, finding_b_id, reason, evidence, confidence FROM chain_relations`

func (r chainRepo) Relations(ctx context.Context, scanJobID string) ([]chains.FindingRelation, error) {
	rows, err := r.q.QueryContext(ctx, chainRelationSelect+` WHERE scan_job_id = ? ORDER BY id`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list chain relations: %w", err)
	}
	defer rows.Close()

	out := []chains.FindingRelation{}
	for rows.Next() {
		var rel chains.FindingRelation
		var relType, evidence string
		if err := rows.Scan(&rel.ID, &rel.ScanJobID, &relType, &rel.FindingAID, &rel.FindingBID, &rel.Reason, &evidence, &rel.Confidence); err != nil {
			return nil, fmt.Errorf("sqlite: scan chain relation: %w", err)
		}
		rel.Type = chains.RelationType(relType)
		if evidence != "" {
			if err := json.Unmarshal([]byte(evidence), &rel.Evidence); err != nil {
				return nil, fmt.Errorf("sqlite: unmarshal relation evidence: %w", err)
			}
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}

const chainCandidateSelect = `SELECT id, scan_job_id, identity_context, finding_ids, relation_ids, endpoints, status, confidence, impact_estimate, reason, missing_evidence FROM chain_candidates`

func (r chainRepo) Candidates(ctx context.Context, scanJobID string) ([]chains.ChainCandidate, error) {
	rows, err := r.q.QueryContext(ctx, chainCandidateSelect+` WHERE scan_job_id = ? ORDER BY id`, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list chain candidates: %w", err)
	}
	defer rows.Close()

	out := []chains.ChainCandidate{}
	for rows.Next() {
		var c chains.ChainCandidate
		var status, findingIDs, relationIDs, endpoints, missing string
		if err := rows.Scan(&c.ID, &c.ScanJobID, &c.IdentityContext, &findingIDs, &relationIDs, &endpoints, &status, &c.Confidence, &c.ImpactEstimate, &c.Reason, &missing); err != nil {
			return nil, fmt.Errorf("sqlite: scan chain candidate: %w", err)
		}
		c.Status = chains.ChainStatus(status)
		for _, pair := range []struct {
			raw string
			out *[]string
		}{{findingIDs, &c.FindingIDs}, {relationIDs, &c.RelationIDs}, {endpoints, &c.Endpoints}, {missing, &c.MissingEvidence}} {
			if pair.raw == "" {
				continue
			}
			if err := json.Unmarshal([]byte(pair.raw), pair.out); err != nil {
				return nil, fmt.Errorf("sqlite: unmarshal chain candidate field: %w", err)
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
