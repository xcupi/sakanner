// Package orchestrator implements sakanner's Phase 3.11 automated scan
// orchestrator: a centralized layer that sequences the ENTIRE existing
// pipeline -- scope validation, Phase 1/2 recon and candidate discovery
// (internal/orchestration.Pipeline), Phase 3.1-3.7 detector execution
// (internal/detection.Engine), Phase 3.8 correlation
// (internal/correlation.Engine), Phase 3.9 risk scoring
// (internal/risk.AssessAll/Rank), and Phase 3.10 evidence/reproduction
// (internal/evidence.BuildPackage) -- from a single user-supplied target
// string to a final, ordered set of evidence.FindingPackage values.
//
// This package owns SEQUENCING ONLY. It contains no vulnerability
// detection logic, no new recon/candidate-discovery mechanism, and no
// scoring/evidence logic of its own -- every one of those already
// exists in the packages listed above and is called here exactly as
// its own public API defines, never forked or reimplemented. See
// docs/phase-3-11-scan-orchestrator.md "Architecture" and "Detector
// independence."
package orchestrator

import (
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/evidence"
)

// Stage is one of the 9 pipeline stages task section 2 names.
type Stage string

const (
	StageScope        Stage = "SCOPE"
	StageRecon        Stage = "RECON"
	StageDiscovery    Stage = "DISCOVERY"
	StageDetection    Stage = "DETECTION"
	StageVerification Stage = "VERIFICATION"
	StageCorrelation  Stage = "CORRELATION"
	StageRisk         Stage = "RISK"
	StageEvidence     Stage = "EVIDENCE"
	StageFinalization Stage = "FINALIZATION"
)

// stageOrder is every Stage in canonical pipeline order -- the ONLY
// place this order is defined; every part of this package that needs
// "all stages in order" (initial ScanState construction, progress
// percentage lookups, documentation generation) reads from this slice.
var stageOrder = []Stage{
	StageScope, StageRecon, StageDiscovery, StageDetection, StageVerification,
	StageCorrelation, StageRisk, StageEvidence, StageFinalization,
}

// StageStatus is one stage's own lifecycle state -- task section 2's
// "start / running / completed / failed / cancelled."
type StageStatus string

const (
	StageStatusPending   StageStatus = "PENDING"
	StageStatusRunning   StageStatus = "RUNNING"
	StageStatusCompleted StageStatus = "COMPLETED"
	StageStatusFailed    StageStatus = "FAILED"
	StageStatusCancelled StageStatus = "CANCELLED"
	// StageStatusSkipped applies to a stage never reached because an
	// earlier stage hard-failed or was cancelled first (task section
	// 12's hard-failure list) -- distinct from StageStatusPending
	// (which just means "not started yet, still might run") so a
	// finished scan's stage list never leaves a later stage looking
	// merely "not started" when it in fact never will.
	StageStatusSkipped StageStatus = "SKIPPED"
)

// Status is the overall scan's lifecycle state -- task section 3.
type Status string

const (
	StatusQueued  Status = "QUEUED"
	StatusRunning Status = "RUNNING"
	// StatusCompleted means every stage that ran, ran cleanly -- no
	// detector error, no stage error, no warning.
	StatusCompleted Status = "COMPLETED"
	// StatusCompletedWithWarnings means the scan reached FINALIZATION
	// (never cancelled, never hard-failed) but at least one detector
	// error, stage-level recoverable error, or warning was recorded
	// along the way -- task section 34's "clearly distinguish successful
	// detector results, failed detectors, and partial scan state."
	StatusCompletedWithWarnings Status = "COMPLETED_WITH_WARNINGS"
	StatusFailed                Status = "FAILED"
	StatusCancelled             Status = "CANCELLED"
)

// ErrorCategory separates fatal/stage/detector/request/warning errors
// -- task section 26's explicit requirement not to conflate them (e.g.
// "do not treat a single HTTP 500 as a scanner failure").
type ErrorCategory string

const (
	// ErrorCategoryFatal is one of task section 12's named hard-failure
	// conditions -- terminates the scan.
	ErrorCategoryFatal ErrorCategory = "FATAL"
	// ErrorCategoryStage is a whole-stage failure that is NOT one of
	// the named hard-failure conditions but still prevented that
	// stage's output from being usable (e.g. a storage write failure
	// inside a stage) -- also terminates the scan, but is reported
	// distinctly from ErrorCategoryFatal so an operator can tell "bad
	// input/scope" apart from "an internal stage broke."
	ErrorCategoryStage ErrorCategory = "STAGE"
	// ErrorCategoryDetector is one detector's isolated failure against
	// one target (a detection.DetectorError) -- never terminates the
	// scan; other detectors and targets continue.
	ErrorCategoryDetector ErrorCategory = "DETECTOR"
	// ErrorCategoryRequest is a single HTTP-request-level failure or
	// unexpected status recorded during recon (e.g. a probe that timed
	// out or 500'd) -- never terminates the scan; recon/detection
	// stages already treat these as per-item, not per-run, failures.
	ErrorCategoryRequest ErrorCategory = "REQUEST"
	// ErrorCategoryWarning is a non-error, still-worth-surfacing
	// observation (e.g. a resource limit was reached and results were
	// bounded) -- never terminates the scan.
	ErrorCategoryWarning ErrorCategory = "WARNING"
)

// ScanError is one recorded error or warning, categorized and
// correlated to the stage/detector it came from -- task sections 26 and
// 28's "every log entry should include scan_id/stage/detector_id where
// applicable" extended to the result object itself, not just logs.
type ScanError struct {
	Category   ErrorCategory `json:"category"`
	Stage      Stage         `json:"stage,omitempty"`
	DetectorID string        `json:"detector_id,omitempty"`
	Message    string        `json:"message"`
	OccurredAt time.Time     `json:"occurred_at"`
}

// StageProgress is one stage's own timing/status snapshot.
type StageProgress struct {
	Stage     Stage       `json:"stage"`
	Status    StageStatus `json:"status"`
	StartedAt *time.Time  `json:"started_at,omitempty"`
	EndedAt   *time.Time  `json:"ended_at,omitempty"`
}

// Counters is task section 3's "counters" field -- deterministic,
// structured facts about how much work each stage did, never derived
// from wall-clock timing.
type Counters struct {
	HostsDiscovered   int   `json:"hosts_discovered"`
	ServicesFound     int   `json:"services_found"`
	HTTPServicesFound int   `json:"http_services_found"`
	TechnologiesFound int   `json:"technologies_found"`
	EndpointsFound    int   `json:"endpoints_found"`
	TargetsConsidered int   `json:"targets_considered"`
	DetectorRuns      int   `json:"detector_runs"`
	RequestsIssued    int64 `json:"requests_issued"`
	RawFindings       int   `json:"raw_findings"`
	Duplicates        int   `json:"duplicates"`
	CanonicalFindings int   `json:"canonical_findings"`
	EvidenceItems     int   `json:"evidence_items"`
}

// FindingsSummary is task section 24's "summary" block.
type FindingsSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// StateSnapshot is an immutable, safe-to-share-across-goroutines copy
// of a ScanState at one instant -- task section 3's minimum scan-state
// fields, plus the stage-by-stage breakdown task section 2 requires.
// Never share the live *ScanState itself across goroutines; always read
// through Snapshot().
type StateSnapshot struct {
	ScanID          string          `json:"scan_id"`
	Target          string          `json:"target"`
	Status          Status          `json:"status"`
	CurrentStage    Stage           `json:"current_stage,omitempty"`
	Stages          []StageProgress `json:"stages"`
	StartedAt       time.Time       `json:"started_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	Duration        time.Duration   `json:"duration_ns"`
	ProgressPercent int             `json:"progress_percent"`
	Counters        Counters        `json:"counters"`
	Errors          []ScanError     `json:"errors,omitempty"`
	FindingsCount   int             `json:"findings_count"`
}

// ReconSummary is task section 24's "recon_summary" block -- read back
// from storage after internal/orchestration.Pipeline.Run completes
// (internal/reporting.Build already aggregates exactly these counts;
// reused here rather than re-queried, see docs/phase-3-11-scan-orchestrator.md
// "Integration of existing modules").
type ReconSummary struct {
	HostCount        int `json:"host_count"`
	ServiceCount     int `json:"service_count"`
	HTTPServiceCount int `json:"http_service_count"`
	TechnologyCount  int `json:"technology_count"`
	EndpointCount    int `json:"endpoint_count"`
}

// InputSummary is Phase 3.13's "scan result must expose: inputs
// discovered, unique endpoints with inputs, input discovery warnings"
// requirement -- read back from storage the same way ReconSummary is
// (see buildInputSummary), never re-derived by re-running discovery.
type InputSummary struct {
	InputCount                int      `json:"input_count"`
	UniqueEndpointsWithInputs int      `json:"unique_endpoints_with_inputs"`
	Warnings                  []string `json:"warnings,omitempty"`
}

// CrawlSummary is Phase 3.15's "scan result must expose: public URLs,
// authenticated URLs, authenticated endpoints" requirement -- read
// back from models.AuthCrawlStats (see buildResult), never re-derived
// by re-running a crawl. Every field is 0 for a scan that never
// crawled at all (recon profile) or never authenticated
// (PublicURLs alone reflects an ordinary unauthenticated crawl's own
// page count).
type CrawlSummary struct {
	PublicURLs             int `json:"public_urls"`
	AuthenticatedURLs      int `json:"authenticated_urls"`
	AuthenticatedEndpoints int `json:"authenticated_endpoints"`
}

// DetectionState distinguishes WHY DetectorRuns is what it is -- Phase
// 3.11.2 task section 5's 3 states, never conflated:
//
//   - DetectionStateExecuted (state A): at least one (detector, target)
//     pair actually ran. DetectorRuns > 0. Findings == 0 here means
//     "detectors executed and found no vulnerabilities" -- a real,
//     meaningful negative result.
//   - DetectionStateNotRun (state B): the DETECTION stage completed
//     cleanly, but zero (detector, target) pairs were eligible to run
//     at all (EligibleTargets == 0) -- most commonly because the
//     crawler is disabled (see docs/phase-3-11-scan-orchestrator.md
//     "Detection readiness"), so no parameterized endpoint targets
//     exist for any current detector's Eligible check to accept.
//     DetectorRuns == 0 here means "no detection was attempted," which
//     is NOT the same claim as "checked and found nothing."
//   - DetectionStateFailed (state C): eligible targets existed but the
//     DETECTION stage itself did not complete (a hard error from
//     detection.Engine.Run, or cancellation/timeout during it) --
//     distinct from a single detector's own isolated failure (task
//     section 11's pre-existing, unrelated error-isolation mechanism,
//     which still produces DetectionStateExecuted with a recorded
//     ErrorCategoryDetector warning, since the STAGE itself still
//     completed).
//   - DetectionStateDisabledByProfile (Phase 3.12): the operator's
//     resolved scan policy (internal/policy.EffectivePolicy, via
//     Options.DetectionDisabled) excluded vulnerability detection
//     entirely for this scan -- e.g. the "recon" profile. Deliberately
//     distinct from DetectionStateNotRun: NOT_RUN means detection was
//     ATTEMPTED but had nothing eligible to examine (a fact about the
//     TARGET); DISABLED_BY_PROFILE means detection was never attempted
//     at all, by POLICY, regardless of what the target contains -- see
//     docs/phase-3-12-scan-profiles.md "Detection policy: disabled by
//     profile vs. not run." This is never treated as a warning (a
//     recon-profile scan finding zero eligible targets is expected
//     behavior, not an anomaly worth flagging).
type DetectionState string

const (
	DetectionStateExecuted DetectionState = "EXECUTED"
	DetectionStateNotRun   DetectionState = "NOT_RUN"
	DetectionStateFailed   DetectionState = "FAILED"
	// DetectionStateDisabledByProfile's value matches the exact literal
	// task's own specification names ("DETECTION_DISABLED_BY_PROFILE"),
	// so it is directly grep-able against that requirement.
	DetectionStateDisabledByProfile DetectionState = "DETECTION_DISABLED_BY_PROFILE"
)

// DetectorSummary is task section 24's "detector_summary" block --
// carries a detection.RunSummary's facts forward without importing
// internal/detection's own type (this package depends on
// internal/detection only through Registry/Executor construction
// parameters the CALLER supplies, never on its result types, keeping
// the dependency direction the same as every other stage). Phase
// 3.11.2 added DetectorsRegistered/DetectorsEnabled/EligibleTargets/
// CanonicalFindings/State -- see DetectionState's doc comment for why
// "detector_runs == 0" alone is not enough to describe what happened.
type DetectorSummary struct {
	// DetectorsRegistered/DetectorsEnabled are static facts about the
	// registry (task section 2) -- always populated, even if the scan
	// never reached the DETECTION stage at all (e.g. SCOPE failed
	// first), since they cost nothing to read (Registry.List(), no
	// scan-state dependency) and are honestly still true regardless of
	// how far the scan got.
	DetectorsRegistered int            `json:"detectors_registered"`
	DetectorsEnabled    int            `json:"detectors_enabled"`
	TargetsConsidered   int            `json:"targets_considered"`
	EligibleTargets     int            `json:"eligible_targets"`
	DetectorRuns        int            `json:"detector_runs"`
	RawFindingsCreated  int            `json:"raw_findings_created"`
	CanonicalFindings   int            `json:"canonical_findings"`
	Duplicates          int            `json:"duplicates"`
	RequestsIssued      int64          `json:"requests_issued"`
	ErrorCount          int            `json:"error_count"`
	State               DetectionState `json:"state"`
}

// Result is task section 24's final ScanResult -- the orchestrator's
// one, complete output.
type Result struct {
	ScanID      string        `json:"scan_id"`
	Target      string        `json:"target"`
	Status      Status        `json:"status"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration_ns"`

	// Profile records the resolved scan policy's own label (Phase 3.12
	// task's "Profile: field in scan output") -- e.g. "recon", "web",
	// "deep", or "web (config-driven, no --profile given)" for the
	// legacy no-profile-but-crawler-enabled-in-config path (see
	// internal/policy.Resolve). Empty when the caller supplied no
	// Options.Policy at all (Options's zero value), preserving every
	// pre-3.12 caller's existing output unchanged.
	Profile string `json:"profile,omitempty"`

	// AuthProfile/AuthState are Phase 3.14's authentication-outcome
	// fields -- task section 7's explicit CLI requirement to
	// distinguish "scan completed without authentication"
	// (AuthState == auth.StateUnauthenticated, AuthProfile == "", the
	// default for every caller that supplies no Options.AuthSession)
	// from "authentication was attempted and failed" from "authenticated
	// scan completed successfully." Populated directly from
	// Options.AuthSession -- this package performs no authentication of
	// its own and never alters a Session's State (see
	// Options.AuthSession's doc comment).
	AuthProfile string     `json:"auth_profile,omitempty"`
	AuthState   auth.State `json:"auth_state"`

	// Identity is Phase 3.16's own addition: the CONFIGURED IDENTITY
	// name (e.g. "account-a") when the scan authenticated via
	// --identity, distinct from AuthProfile (the underlying auth
	// profile's own name, e.g. "customer-login" -- see
	// docs/phase-3-16-multi-identity.md "Auth Profile vs. Identity").
	// Empty for a scan authenticated via a bare --auth-profile (no
	// identity wrapper) or not authenticated at all -- populated
	// directly from Options.AuthSession.IdentityName, exactly like
	// AuthProfile is populated from Options.AuthSession.ProfileName.
	Identity string `json:"identity,omitempty"`

	// AuthenticatedRequests/SessionExpired are Phase 3.15's
	// authenticated-crawling summary fields, read back verbatim from
	// the pipeline's own models.AuthCrawlStats (see that type's doc
	// comment) -- this package computes neither value itself, only
	// carries them into the final Result exactly like ReconSummary/
	// InputSummary already do for their own upstream data. Both are
	// zero-value (0 / false) for every scan that never used
	// authenticated crawling -- task's "preserve backward
	// compatibility with unauthenticated scanning."
	AuthenticatedRequests int  `json:"authenticated_requests,omitempty"`
	SessionExpired        bool `json:"session_expired,omitempty"`

	ReconSummary ReconSummary `json:"recon_summary"`
	InputSummary InputSummary `json:"input_summary"`
	// CrawlSummary is Phase 3.15's "clearly distinguish authenticated
	// vs unauthenticated discovered resources" requirement -- task
	// section 8 of the phase's own goal list.
	CrawlSummary    CrawlSummary    `json:"crawl_summary"`
	DetectorSummary DetectorSummary `json:"detector_summary"`

	// Findings is in Phase 3.9's deterministic risk-ranked order --
	// task section 25: the orchestrator never reorders it further.
	Findings []evidence.FindingPackage `json:"findings"`

	Errors   []ScanError `json:"errors,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`

	Summary FindingsSummary `json:"summary"`
}
