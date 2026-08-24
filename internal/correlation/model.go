// Package correlation implements sakanner's Phase 3.8 finding
// correlation and deduplication engine: a centralized layer that
// receives models.Finding values from every detector (unchanged --
// see docs/phase-3-8-finding-correlation.md "Detector independence")
// and produces a normalized, deterministic, non-duplicated
// CanonicalFinding set.
//
// This package is entirely additive. It reads pkg/models.Finding
// values (the existing, unmodified Phase 3.1 detector-facing
// contract) and never mutates them, never touches
// internal/detection.Engine's own dedup pass, and requires no change
// to any existing detector. See "Detector independence" and "API /
// internal interface" in docs/phase-3-8-finding-correlation.md.
package correlation

import (
	"time"

	"sakanner/pkg/models"
)

// Asset is a CanonicalFinding's normalized network/HTTP location --
// task section 1's "asset" block.
type Asset struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
}

// HTTPContext is a CanonicalFinding's normalized request shape --
// task section 1's "http" block.
type HTTPContext struct {
	Method    string `json:"method"`
	Parameter string `json:"parameter,omitempty"`
	// Location is one of "query"/"body"/"header"/"cookie"/"unspecified".
	// Every detector in this project today only ever produces
	// query-parameter findings, so this is "query" in practice for
	// every real finding -- see "Parameter normalization" in
	// docs/phase-3-8-finding-correlation.md for why the field (and the
	// identity algorithm that reads it) is built to support the other
	// values once a detector produces one, rather than hardcoding
	// "query" everywhere.
	Location string `json:"location,omitempty"`
}

// Resource is a CanonicalFinding's resource-level identity --
// task section 1's "resource" block. Populated only for
// vulnerability_type "idor" (see "Resource-aware identity" in
// docs/phase-3-8-finding-correlation.md for why); empty for every
// other type.
type Resource struct {
	Identifier string `json:"identifier,omitempty"`
}

// Status is a CanonicalFinding's lifecycle state (task section 12).
type Status string

const (
	// StatusNew is assigned to a canonical finding backed by exactly
	// one distinct evidence signature -- a single probe/observation,
	// not yet independently corroborated.
	StatusNew Status = "NEW"

	// StatusConfirmed is assigned once 2 or more DISTINCT (non-
	// duplicate) evidence signatures corroborate the same identity --
	// see "Confidence consolidation" for what "distinct" means.
	StatusConfirmed Status = "CONFIRMED"

	// StatusDuplicate is never assigned to an OUTPUT CanonicalFinding
	// (duplicates are merged away, not listed separately) -- it
	// describes a RAW INPUT finding's classification in an
	// IngestResult (see engine.go), for callers that want to inspect
	// per-input outcomes.
	StatusDuplicate Status = "DUPLICATE"

	// StatusResolved is defined for a future phase's re-scan/
	// remediation-tracking workflow and is NEVER assigned by this
	// phase's Engine -- there is no re-scan comparison capability yet.
	// See "Finding status" in docs/phase-3-8-finding-correlation.md
	// "Limitations."
	StatusResolved Status = "RESOLVED"
)

// EvidenceItem is a deduplicated evidence entry inside a
// CanonicalFinding -- a content-addressed view of pkg/models.Evidence
// (ID/FindingID/CreatedAt are per-record bookkeeping, not part of an
// evidence item's identity; see "Evidence merging").
type EvidenceItem struct {
	Kind    models.EvidenceKind `json:"kind"`
	Content string              `json:"content"`
}

// CanonicalFinding is this package's output type -- task section 1's
// canonical finding model. Detectors never produce this directly; the
// Engine builds it from one or more contributing models.Finding
// values sharing the same Identity.
type CanonicalFinding struct {
	FindingID         string          `json:"finding_id"`
	ScanID            string          `json:"scan_id"`
	DetectorID        string          `json:"detector_id"`
	VulnerabilityType string          `json:"vulnerability_type"`
	Title             string          `json:"title"`
	Asset             Asset           `json:"asset"`
	HTTP              HTTPContext     `json:"http"`
	Resource          Resource        `json:"resource"`
	Severity          models.Severity `json:"severity"`
	Confidence        float64         `json:"confidence"`
	Status            Status          `json:"status"`
	Evidence          []EvidenceItem  `json:"evidence,omitempty"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
	// Metadata carries small, bounded, deterministic facts about how
	// this canonical finding was assembled -- never arbitrary detector
	// output. See "Evidence limits" for what's stored here and why.
	Metadata map[string]string `json:"metadata,omitempty"`
}
