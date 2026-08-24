// Package risk implements sakanner's Phase 3.9 risk scoring and
// prioritization engine: a deterministic, explainable layer that
// consumes ONLY internal/correlation.CanonicalFinding values (Phase
// 3.8's output -- never raw detector output, never internal/detection
// directly) and produces a RiskScore, a Priority band, a reproducible
// score breakdown, and a human-readable explanation for each.
//
// This is an internal deterministic prioritization model, not CVSS or
// EPSS. No network request, filesystem access, external service call,
// or LLM invocation happens anywhere in this package -- see
// docs/phase-3-9-risk-scoring.md "Security considerations" and
// security_test.go.
package risk

import (
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// ConfidenceTier buckets a CanonicalFinding's continuous Confidence
// value into the 3 categories the scoring formula's weight table is
// defined over (task section 3). See weights.go for the exact
// multipliers and derive.go for how a real finding's float64
// Confidence maps into one of these.
type ConfidenceTier string

const (
	ConfidenceLow    ConfidenceTier = "LOW"
	ConfidenceMedium ConfidenceTier = "MEDIUM"
	ConfidenceHigh   ConfidenceTier = "HIGH"
)

// VerificationTier represents how independently corroborated a
// finding is -- task section 7. See derive.go's DeriveFactors for the
// exact, documented derivation from a real CanonicalFinding.
type VerificationTier string

const (
	VerificationUnverified VerificationTier = "UNVERIFIED"
	VerificationSuspicious VerificationTier = "SUSPICIOUS"
	VerificationVerified   VerificationTier = "VERIFIED"
)

// ExposureTier represents how reachable the affected asset is -- task
// section 8. UNKNOWN is the safe default whenever this project's
// current recon model carries no explicit exposure signal for a
// finding (which is every real finding today -- see derive.go).
type ExposureTier string

const (
	ExposureInternal       ExposureTier = "INTERNAL"
	ExposureRestricted     ExposureTier = "RESTRICTED"
	ExposureInternetFacing ExposureTier = "INTERNET_FACING"
	ExposureUnknown        ExposureTier = "UNKNOWN"
)

// Priority is a risk score's coarse triage band -- task section 4.
type Priority string

const (
	PriorityLow      Priority = "LOW"
	PriorityMedium   Priority = "MEDIUM"
	PriorityHigh     Priority = "HIGH"
	PriorityCritical Priority = "CRITICAL"
)

// RiskFactors is the risk engine's normalized, categorical input --
// every factor the scoring formula (score.go) actually consumes.
// Constructing this directly (rather than only via DeriveFactors) is
// how matrix_test.go and monotonicity_test.go exercise every
// combination of the 4×3×3×4 factor space independently of what any
// real CanonicalFinding happens to produce.
type RiskFactors struct {
	Severity     models.Severity
	Confidence   ConfidenceTier
	Verification VerificationTier
	Exposure     ExposureTier
}

// AssetContext is optional, caller-supplied context about the
// affected asset -- task section 9. Every field except Exposure is
// carried through to the Assessment for display only; the scoring
// formula never reads Host/Port/Protocol/Application/Endpoint/
// Environment (task section 17 forbids inventing additional scoring
// factors beyond the documented model). A nil AssetContext, or one
// with an empty Exposure, defaults to ExposureUnknown -- task section
// 8's "if exposure is unknown: UNKNOWN. Do not assume
// internet-facing."
type AssetContext struct {
	Host        string
	Port        int
	Protocol    string
	Application string
	Endpoint    string
	Environment string
	Exposure    ExposureTier
}

// ScoreBreakdown is every factor the formula used, retained so a score
// can be reproduced and audited -- task section 11.
type ScoreBreakdown struct {
	SeverityBase           int      `json:"severity_base"`
	SeverityRecognized     bool     `json:"severity_recognized"`
	ConfidenceMultiplier   float64  `json:"confidence_multiplier"`
	VerificationMultiplier float64  `json:"verification_multiplier"`
	ExposureMultiplier     float64  `json:"exposure_multiplier"`
	RawScore               float64  `json:"raw_score"`
	RiskScore              int      `json:"risk_score"`
	Priority               Priority `json:"priority"`
}

// Assessment is the risk engine's output for one canonical finding.
// Severity is the finding's ORIGINAL, unmodified severity (task
// section 1/5 -- risk scoring never downgrades or overwrites it).
type Assessment struct {
	FindingID         string          `json:"finding_id"`
	ScanID            string          `json:"scan_id"`
	VulnerabilityType string          `json:"vulnerability_type"`
	Severity          models.Severity `json:"severity"`
	Factors           RiskFactors     `json:"factors"`
	Breakdown         ScoreBreakdown  `json:"breakdown"`
	RiskScore         int             `json:"risk_score"`
	Priority          Priority        `json:"priority"`
	Explanation       string          `json:"explanation"`
	Asset             AssetSummary    `json:"asset"`
	AssessedAt        time.Time       `json:"assessed_at"`
}

// AssetSummary mirrors the finding's own asset location plus whatever
// optional AssetContext the caller supplied, for display -- never
// consulted by the scoring formula itself beyond Exposure (already
// captured in Factors.Exposure).
type AssetSummary struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Path        string `json:"path"`
	Protocol    string `json:"protocol,omitempty"`
	Application string `json:"application,omitempty"`
	Environment string `json:"environment,omitempty"`
}

func assetSummaryOf(cf correlation.CanonicalFinding, ctx *AssetContext) AssetSummary {
	s := AssetSummary{Host: cf.Asset.Host, Port: cf.Asset.Port, Path: cf.Asset.Path, Protocol: cf.Asset.Scheme}
	if ctx != nil {
		if ctx.Application != "" {
			s.Application = ctx.Application
		}
		if ctx.Environment != "" {
			s.Environment = ctx.Environment
		}
		if ctx.Protocol != "" {
			s.Protocol = ctx.Protocol
		}
	}
	return s
}
