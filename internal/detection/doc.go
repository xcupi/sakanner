// Package detection is sakanner's Phase 3.1 vulnerability detection
// framework: a Registry of pluggable Detector implementations, a
// scope-safe request Executor every detector must use to touch a
// target, and an Engine that runs registered detectors against a
// completed scan job's Phase 2 recon output, normalizes their results
// into pkg/models.Finding rows, deduplicates them, and persists them
// through the existing storage.Store.
//
// This package implements the FRAMEWORK only. It ships zero real
// vulnerability detectors -- see docs/phase-3-1-detection-engine.md
// "How to implement a new detector" for how a future phase adds one
// without modifying anything in this package. detectiontest (a sibling
// package) provides a Mock detector for testing the framework itself;
// it is test-support code, not a real detector, and is never registered
// in production.
package detection
