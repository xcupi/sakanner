// Package reporting generates sakanner's scan output formats: a
// machine-readable JSON export and a human-readable Markdown summary.
// Both read from storage.Store rather than the pipeline directly, so a
// report can be regenerated at any time from persisted results.
package reporting

import (
	"context"
	"encoding/json"
	"fmt"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// Report is the full JSON export for one scan job.
type Report struct {
	Job          models.ScanJob       `json:"job"`
	Assets       []models.Asset       `json:"assets"`
	Hosts        []models.Host        `json:"hosts"`
	DNSRecords   []models.DNSRecord   `json:"dns_records"`
	Services     []models.Service     `json:"services"`
	HTTPServices []models.HTTPService `json:"http_services"`
	Technologies []models.Technology  `json:"technologies"`
	Endpoints    []models.Endpoint    `json:"endpoints"`
	Parameters   []models.Parameter   `json:"parameters"`
	Findings     []models.Finding     `json:"findings"`
}

// Build assembles a Report for scanJobID by reading every related record
// from store.
func Build(ctx context.Context, store storage.Store, scanJobID string) (*Report, error) {
	job, err := store.ScanJobs().Get(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading scan job: %w", err)
	}

	assets, err := store.Assets().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading assets: %w", err)
	}
	hosts, err := store.Hosts().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading hosts: %w", err)
	}
	dnsRecords, err := store.DNSRecords().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading dns records: %w", err)
	}
	services, err := store.Services().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading services: %w", err)
	}
	httpServices, err := store.HTTPServices().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading http services: %w", err)
	}
	technologies, err := store.Technologies().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading technologies: %w", err)
	}
	endpointsList, err := store.Endpoints().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading endpoints: %w", err)
	}
	parametersList, err := store.Parameters().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading parameters: %w", err)
	}
	findings, err := store.Findings().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("reporting: loading findings: %w", err)
	}

	return &Report{
		Job:          job,
		Assets:       assets,
		Hosts:        hosts,
		DNSRecords:   dnsRecords,
		Services:     services,
		HTTPServices: httpServices,
		Technologies: technologies,
		Endpoints:    endpointsList,
		Parameters:   parametersList,
		Findings:     findings,
	}, nil
}

// JSON renders r as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("reporting: marshal JSON: %w", err)
	}
	return b, nil
}
