// Package storage defines sakanner's persistence interfaces. Concrete
// backends (internal/storage/sqlite today, potentially a Postgres
// implementation later) satisfy these interfaces so callers -- CLI
// commands and the orchestration pipeline -- never depend on a specific
// database.
package storage

import (
	"context"

	"sakanner/internal/chains"
	"sakanner/pkg/models"
)

// Store is the full repository surface sakanner's Phase 1 pipeline and
// CLI depend on.
type Store interface {
	Close() error
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error

	Targets() TargetRepository
	ScopeRules() ScopeRuleRepository
	ScanJobs() ScanJobRepository
	Assets() AssetRepository
	Hosts() HostRepository
	DNSRecords() DNSRecordRepository
	Services() ServiceRepository
	HTTPServices() HTTPServiceRepository
	Technologies() TechnologyRepository
	Endpoints() EndpointRepository
	Parameters() ParameterRepository
	Findings() FindingRepository
	// Chains persists Phase 3.30's internal/chains correlation output --
	// Phase 3.31's own additive integration. internal/chains itself
	// never imports this package (or anything else in the scanner/CLI/
	// reporting layers) -- this is the ONE place the dependency runs,
	// and it runs downward only (storage depends on the standalone
	// chains package, never the reverse), exactly mirroring how this
	// package already depends on the equally standalone pkg/models.
	Chains() ChainRepository

	// WithTx runs fn against a Store bound to a single transaction, so a
	// pipeline stage can persist a batch of results atomically. fn's Store
	// must not be used after WithTx returns.
	WithTx(ctx context.Context, fn func(Store) error) error
}

// TargetRepository persists operator-supplied scan targets.
type TargetRepository interface {
	Create(ctx context.Context, t models.Target) error
	Get(ctx context.Context, id string) (models.Target, error)
	List(ctx context.Context) ([]models.Target, error)
	Delete(ctx context.Context, id string) error
}

// ScopeRuleRepository persists operator-defined authorization rules.
type ScopeRuleRepository interface {
	Create(ctx context.Context, r models.ScopeRule) error
	Get(ctx context.Context, id string) (models.ScopeRule, error)
	List(ctx context.Context) ([]models.ScopeRule, error)
	Delete(ctx context.Context, id string) error
}

// ScanJobRepository persists scan job lifecycle state.
type ScanJobRepository interface {
	Create(ctx context.Context, j models.ScanJob) error
	Get(ctx context.Context, id string) (models.ScanJob, error)
	List(ctx context.Context) ([]models.ScanJob, error)
	Update(ctx context.Context, j models.ScanJob) error
	Delete(ctx context.Context, id string) error
}

// AssetRepository persists discovered names for a scan job.
type AssetRepository interface {
	Create(ctx context.Context, a models.Asset) error
	Get(ctx context.Context, id string) (models.Asset, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Asset, error)
	Delete(ctx context.Context, id string) error
}

// HostRepository persists resolved IPs for a scan job.
type HostRepository interface {
	Create(ctx context.Context, h models.Host) error
	Get(ctx context.Context, id string) (models.Host, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Host, error)
	Delete(ctx context.Context, id string) error
}

// DNSRecordRepository persists non-address (CNAME/MX/TXT/NS) DNS records
// for a scan job.
type DNSRecordRepository interface {
	Create(ctx context.Context, r models.DNSRecord) error
	Get(ctx context.Context, id string) (models.DNSRecord, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.DNSRecord, error)
	Delete(ctx context.Context, id string) error
}

// ServiceRepository persists open ports for a scan job.
type ServiceRepository interface {
	Create(ctx context.Context, s models.Service) error
	Get(ctx context.Context, id string) (models.Service, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Service, error)
	Delete(ctx context.Context, id string) error
}

// HTTPServiceRepository persists HTTP probe results for a scan job.
type HTTPServiceRepository interface {
	Create(ctx context.Context, h models.HTTPService) error
	Get(ctx context.Context, id string) (models.HTTPService, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.HTTPService, error)
	Delete(ctx context.Context, id string) error
}

// TechnologyRepository persists fingerprinted technologies for a scan job.
type TechnologyRepository interface {
	Create(ctx context.Context, t models.Technology) error
	Get(ctx context.Context, id string) (models.Technology, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Technology, error)
	Delete(ctx context.Context, id string) error
}

// EndpointRepository persists discovered endpoints (crawled pages,
// forms, and script references) for a scan job.
type EndpointRepository interface {
	Create(ctx context.Context, e models.Endpoint) error
	Get(ctx context.Context, id string) (models.Endpoint, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Endpoint, error)
	Delete(ctx context.Context, id string) error
}

// ParameterRepository persists discovered application inputs (Phase
// 3.13's normalized input model -- internal/parameters) for a scan
// job. Mirrors EndpointRepository's own shape exactly.
type ParameterRepository interface {
	Create(ctx context.Context, p models.Parameter) error
	Get(ctx context.Context, id string) (models.Parameter, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Parameter, error)
	Delete(ctx context.Context, id string) error
}

// FindingRepository persists findings for a scan job. Expected to be
// empty in Phase 1 since detection/validation are not yet implemented,
// but the CLI's `findings`/`report` commands depend on this shape now.
type FindingRepository interface {
	Create(ctx context.Context, f models.Finding) error
	Get(ctx context.Context, id string) (models.Finding, error)
	ListByScanJob(ctx context.Context, scanJobID string) ([]models.Finding, error)
	Delete(ctx context.Context, id string) error
}

// ChainRepository persists Phase 3.30's chains.FindingRelation/
// chains.ChainCandidate values for a scan job -- Phase 3.31's own
// addition. SaveResult replaces (never appends to) any previously
// saved result for scanJobID, so it is always safe to call again for
// the same scan and always ends in the identical persisted state for
// the identical input -- the "loading a scan must reproduce the same
// chain structure deterministically" requirement. Relations/Candidates
// are read back in a fixed, deterministic order (by their own
// content-derived ID, ascending) -- never database row-insertion order.
type ChainRepository interface {
	SaveResult(ctx context.Context, scanJobID string, result chains.Result) error
	Relations(ctx context.Context, scanJobID string) ([]chains.FindingRelation, error)
	Candidates(ctx context.Context, scanJobID string) ([]chains.ChainCandidate, error)
}
