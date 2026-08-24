// Package parameters implements sakanner's Phase 3.13 Parameter &
// Input Discovery Engine: it discovers and normalizes application
// inputs (URL query parameters, HTML form fields, JSON body fields,
// and -- where reliable evidence exists -- variable URL path segments)
// from already-crawled internal/crawler.Page data, producing a
// canonical pkg/models.Parameter representation existing vulnerability
// detectors can consume without each re-parsing HTML, JSON, or raw
// URLs themselves.
//
// This package performs no I/O of its own and issues no network
// requests -- exactly like internal/endpoints.Normalize, which it
// mirrors closely: a pure transformation from already-fetched crawl
// data to a deterministic, deduplicated slice of candidates, with
// ID/ScanJobID/EndpointID/CreatedAt filled in by the caller
// (internal/orchestration.Pipeline) at persistence time. See
// docs/phase-3-13-parameter-discovery.md for the full design,
// including which input sources are and are not wired into the live
// pipeline in this phase, and why.
//
// This package contains no vulnerability detection logic, no
// exploitation, and no fuzzing -- it observes values already present
// in already-fetched application responses; it never substitutes a
// payload for an observed value.
package parameters
