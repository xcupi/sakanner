// Package models defines the core data types shared across sakanner's
// pipeline stages, storage layer, and reporting.
package models

import "time"

// TargetType identifies what kind of value a Target holds.
type TargetType string

const (
	TargetTypeDomain TargetType = "domain"
	TargetTypeHost   TargetType = "host"
	TargetTypeIP     TargetType = "ip"
	TargetTypeCIDR   TargetType = "cidr"
)

// Target is an operator-supplied, in-scope entry point for a scan.
type Target struct {
	ID        string     `json:"id"`
	Value     string     `json:"value"`
	Type      TargetType `json:"type"`
	Note      string     `json:"note,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ScopeRuleType identifies how a ScopeRule's Value is matched.
type ScopeRuleType string

const (
	ScopeRuleExactHost    ScopeRuleType = "exact_host"
	ScopeRuleDomainSuffix ScopeRuleType = "domain_suffix"
	ScopeRuleCIDR         ScopeRuleType = "cidr"
)

// ScopeAction is the outcome a ScopeRule applies when it matches.
type ScopeAction string

const (
	ScopeActionAllow ScopeAction = "allow"
	ScopeActionDeny  ScopeAction = "deny"
)

// ScopeRule is an operator-defined authorization rule. Deny rules always
// override allow rules, and an unmatched host/IP is denied by default.
type ScopeRule struct {
	ID        string        `json:"id"`
	Value     string        `json:"value"`
	Type      ScopeRuleType `json:"type"`
	Action    ScopeAction   `json:"action"`
	Note      string        `json:"note,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// ScanJobStatus tracks a ScanJob's lifecycle.
type ScanJobStatus string

const (
	ScanJobStatusPending   ScanJobStatus = "pending"
	ScanJobStatusRunning   ScanJobStatus = "running"
	ScanJobStatusCompleted ScanJobStatus = "completed"
	ScanJobStatusFailed    ScanJobStatus = "failed"
	ScanJobStatusCancelled ScanJobStatus = "cancelled"
)

// ScanJob represents one execution of the scanning pipeline against a set
// of targets. ScopeSnapshot is the frozen set of ScopeRules in effect for
// this job, captured at start time so results stay reproducible even if
// scope rules are edited afterward.
type ScanJob struct {
	ID            string        `json:"id"`
	TargetIDs     []string      `json:"target_ids"`
	Status        ScanJobStatus `json:"status"`
	Error         string        `json:"error,omitempty"`
	ScopeSnapshot []ScopeRule   `json:"scope_snapshot"`
	Config        string        `json:"config,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    *time.Time    `json:"finished_at,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	// Warnings carries non-fatal, structured warnings produced DURING
	// this run (Phase 3.13: input discovery resource-limit warnings) --
	// deliberately transient, not persisted by the storage layer (no
	// column backs it): it exists only on the in-memory value
	// Pipeline.Run returns directly to its immediate caller, for that
	// one run. A ScanJob later re-loaded from storage always has this
	// empty -- callers wanting a permanent record should read the
	// structured log events (input_discovery_warning) this same data
	// is also emitted through.
	Warnings []string `json:"warnings,omitempty"`
	// AuthCrawlStats carries Phase 3.15's authenticated-crawling summary
	// counters -- the SAME "deliberately transient, not persisted"
	// contract as Warnings above (no storage column backs it; a ScanJob
	// re-loaded from storage always has this at its zero value). See
	// AuthCrawlStats' own doc comment.
	AuthCrawlStats AuthCrawlStats `json:"auth_crawl_stats,omitempty"`
}

// AuthCrawlStats summarizes what an authenticated crawl actually did --
// Phase 3.15's "clearly distinguish authenticated vs unauthenticated
// discovered resources" requirement, and its session-expiration
// detection signal. Computed once per Pipeline.Run call from the
// crawl's own in-memory results (crawler.Page.StatusCode among pages
// fetched with session cookies/headers attached); never read back from
// storage, for the same reason Warnings isn't -- it describes what
// happened during THIS run, not a durable fact about the target.
type AuthCrawlStats struct {
	// PublicPages/AuthenticatedPages are page fetches (crawler.Page
	// results) split by whether session cookies/headers were attached
	// for that page's own target -- every page from one crawlTarget
	// call is uniformly one or the other, since a session (if any) is
	// attached once per target, not varied per page within it.
	PublicPages        int `json:"public_pages"`
	AuthenticatedPages int `json:"authenticated_pages"`
	// AuthenticatedRequests counts actual HTTP page fetches made while
	// carrying session state -- identical to AuthenticatedPages today
	// (one fetch per discovered page), kept as its own named field
	// because it is a distinct CONCEPT (task's "Authenticated Requests:
	// 37") that could diverge from a page count in the future (e.g. if
	// a future phase adds authenticated requests that are not
	// themselves crawled pages, such as an authenticated API probe).
	AuthenticatedRequests int `json:"authenticated_requests"`
	// AuthenticatedEndpoints is the count of persisted Endpoint rows
	// that came from an authenticated target's crawl.
	AuthenticatedEndpoints int `json:"authenticated_endpoints"`
	// SessionExpired is true if ANY authenticated page fetch during
	// this run returned 401/403, or landed on what looks like the
	// login page itself (see internal/orchestration's
	// detectSessionExpired) -- task section F's "detect the condition."
	// This never aborts the crawl or triggers a re-login attempt (see
	// that function's own doc comment for why); it is purely an
	// observability signal surfaced to the operator.
	SessionExpired bool `json:"session_expired"`
}

// ScanResult is a summary rollup of what a ScanJob produced, used for
// quick status reporting without joining every child table.
type ScanResult struct {
	ScanJobID    string `json:"scan_job_id"`
	AssetCount   int    `json:"asset_count"`
	HostCount    int    `json:"host_count"`
	ServiceCount int    `json:"service_count"`
	HTTPCount    int    `json:"http_count"`
	FindingCount int    `json:"finding_count"`
}

// Asset is a discovered name (e.g. subdomain) belonging to a scan job,
// prior to DNS resolution.
type Asset struct {
	ID        string    `json:"id"`
	ScanJobID string    `json:"scan_job_id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// Host is a resolved IP address for an Asset.
type Host struct {
	ID        string    `json:"id"`
	ScanJobID string    `json:"scan_job_id"`
	AssetID   string    `json:"asset_id"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
}

// DNSRecordType identifies a DNSRecord's record type.
type DNSRecordType string

const (
	DNSRecordTypeCNAME DNSRecordType = "CNAME"
	DNSRecordTypeMX    DNSRecordType = "MX"
	DNSRecordTypeTXT   DNSRecordType = "TXT"
	DNSRecordTypeNS    DNSRecordType = "NS"
)

// DNSRecord is a non-address DNS record (CNAME/MX/TXT/NS) found for an
// Asset. A/AAAA records are represented by Host, not DNSRecord, since
// they're what the rest of the pipeline dials.
type DNSRecord struct {
	ID        string        `json:"id"`
	ScanJobID string        `json:"scan_job_id"`
	AssetID   string        `json:"asset_id"`
	Type      DNSRecordType `json:"type"`
	Value     string        `json:"value"`
	Priority  int           `json:"priority,omitempty"` // MX preference; unused (0) for other types
	CreatedAt time.Time     `json:"created_at"`
}

// Service is an open TCP port discovered on a Host.
type Service struct {
	ID        string    `json:"id"`
	ScanJobID string    `json:"scan_job_id"`
	HostID    string    `json:"host_id"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Banner    string    `json:"banner,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// RedirectHop is one hop of the chain an HTTPService's request followed
// before reaching its final response, in order.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// HTTPService is the result of probing a Service that speaks HTTP(S).
type HTTPService struct {
	ID            string            `json:"id"`
	ScanJobID     string            `json:"scan_job_id"`
	ServiceID     string            `json:"service_id"`
	URL           string            `json:"url"`
	Scheme        string            `json:"scheme"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	RedirectChain []RedirectHop     `json:"redirect_chain,omitempty"`
	TLSSubject    string            `json:"tls_subject,omitempty"`
	TLSIssuer     string            `json:"tls_issuer,omitempty"`
	TLSNotAfter   *time.Time        `json:"tls_not_after,omitempty"`
	TLSVersion    string            `json:"tls_version,omitempty"`     // e.g. "TLS 1.3"
	TLSSelfSigned bool              `json:"tls_self_signed,omitempty"` // subject == issuer (a heuristic, not cryptographic proof)
	TLSSANs       []string          `json:"tls_sans,omitempty"`        // subject alternative names (DNS + IP)
	CreatedAt     time.Time         `json:"created_at"`
}

// Technology is a fingerprinted piece of software identified on an
// HTTPService.
type Technology struct {
	ID            string  `json:"id"`
	ScanJobID     string  `json:"scan_job_id"`
	HTTPServiceID string  `json:"http_service_id"`
	Name          string  `json:"name"`
	Version       string  `json:"version,omitempty"`
	Category      string  `json:"category,omitempty"`
	Confidence    float64 `json:"confidence"`
	// Source identifies what produced this finding: "fingerprint" for
	// sakanner's own built-in signature matcher, or an external tool's
	// name (e.g. "httpx") once such a backend is in use -- confidence
	// semantics can differ by source, so this is kept distinct from
	// Category.
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Endpoint is a discovered URL path, reserved for the crawling/endpoint
// discovery stages (not populated in Phase 1).
type Endpoint struct {
	ID            string `json:"id"`
	ScanJobID     string `json:"scan_job_id"`
	HTTPServiceID string `json:"http_service_id"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	Source        string `json:"source"`
	// IdentityContext is Phase 3.16's own addition: the CONFIGURED
	// IDENTITY name (e.g. "account-a") whose authenticated session was
	// attached to the crawl that discovered this endpoint, or "" for an
	// unauthenticated crawl or one authenticated via a bare
	// --auth-profile (no identity wrapper). Never a credential --
	// identity labels are operator-chosen, safe strings, exactly like
	// AuthProfile names already are. Two endpoints with the identical
	// Path/Method/Source discovered under two DIFFERENT identities are
	// never merged into one row (task section 7's "do not merge
	// identity-specific observations merely because their URL is
	// identical") -- each scan job's own Endpoint rows already keep
	// them structurally separate per scan, and this field makes that
	// fact directly visible on the row itself, without requiring a
	// join back to whichever scan job produced it.
	IdentityContext string `json:"identity_context,omitempty"`
	// APICandidate, APIEvidence, and ResponseContentType are Phase
	// 3.18's own addition -- see internal/endpoints.ClassifyAPI. false/
	// ""/"" (the Go zero values) for every endpoint discovered before
	// Phase 3.18, and for every SourceLink/SourceForm/SourceJavaScript
	// endpoint today (only a SourceCrawl endpoint -- one this scan
	// itself fetched -- carries direct response evidence to classify
	// with). Never authoritative on its own: APIEvidence always names
	// which signal(s) produced APICandidate == true, so a consumer can
	// judge reliability rather than trust a bare boolean.
	APICandidate bool `json:"api_candidate,omitempty"`
	// APIEvidence is a comma-joined, human-readable list of the
	// reasons APICandidate is true, e.g.
	// "response_content_type_json,path_heuristic". Empty when
	// APICandidate is false.
	APIEvidence string `json:"api_evidence,omitempty"`
	// ResponseContentType is the Content-Type observed when this
	// endpoint was fetched (SourceCrawl only) -- "" for every endpoint
	// this scan did not itself fetch, and for every endpoint discovered
	// before Phase 3.18.
	ResponseContentType string `json:"response_content_type,omitempty"`
	// ActionOrigin is Phase 3.21's own addition: the normalized
	// "scheme://host:port" origin a discovered HTML form's own
	// action="..." attribute resolved to, computed BEFORE Path (above)
	// discarded the host -- populated only for Source == "form" rows,
	// "" for every other source (including every row that existed
	// before this field). Lets BuildTargets refuse to build an active-
	// mutation Target for a form whose action points somewhere other
	// than the HTTPService this Endpoint is actually associated with --
	// see docs/phase-3-21-form-mutation.md section 1 Finding 3 for why
	// this matters: without it, a cross-origin form's fields would be
	// structurally indistinguishable from a same-origin one.
	ActionOrigin string    `json:"action_origin,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// Parameter is a discovered application input on an Endpoint -- Phase
// 3.13's normalized input model, populated by internal/parameters from
// already-crawled pages (see that package's doc comment for the full
// discovery/normalization design). Reserved but unpopulated through
// Phase 3.12.
type Parameter struct {
	ID         string `json:"id"`
	ScanJobID  string `json:"scan_job_id"`
	EndpointID string `json:"endpoint_id"`
	Name       string `json:"name"`
	// Location is one of "query", "path", "form", "json", "header", or
	// "cookie" -- see internal/parameters.Location for the canonical
	// enum these string values come from. Two inputs with the same Name
	// but different Location are always distinct (e.g. a query
	// parameter "q" and a JSON body field "q" on the same endpoint are
	// NOT the same input).
	Location string `json:"location"`
	// Classification is a coarser grouping derived FROM Location (never
	// independently authoritative -- see internal/parameters.ClassificationFor):
	// "PARAMETER" (query), "PATH_INPUT" (path), "FORM_FIELD" (form),
	// "JSON_FIELD" (json).
	Classification string `json:"classification,omitempty"`
	// Method is the HTTP method the endpoint carrying this input uses
	// (e.g. "GET", "POST") -- the same input name in the same location
	// under a different method is a distinct input (GET /search?q=x vs
	// POST /search?q=x are not merged).
	Method string `json:"method,omitempty"`
	// Value is the original observed/default value already present in
	// the crawled markup or URL -- never a payload. Redacted (replaced
	// with internal/evidence.RedactedPlaceholder) before being set here
	// when Name matches internal/evidence.IsSensitiveFieldName, so a
	// secret is never persisted even in this "as observed" form.
	Value string `json:"value,omitempty"`
	// Source records HOW this input was discovered (e.g. "url_query",
	// "html_form", "json_body", "path_inference") -- distinct from
	// Location, which records WHERE the value is transmitted.
	Source string `json:"source,omitempty"`
	// ContentType is set for body-carried inputs (Location == "form" or
	// "json") -- the request content type the value would be submitted
	// under.
	ContentType string `json:"content_type,omitempty"`
	// Required is nil when not known from available evidence (the
	// common case: HTML/URL discovery has no reliable "is this
	// required" signal), true/false only when discovery evidence
	// actually established it.
	Required *bool `json:"required,omitempty"`
	// EvidenceRef optionally names where more detail about this
	// input's discovery can be found (e.g. an endpoint or page
	// reference) -- opaque to this model, interpreted by callers.
	EvidenceRef string `json:"evidence_ref,omitempty"`
	// IdentityContext mirrors Endpoint.IdentityContext exactly -- see
	// that field's own doc comment. Always equal to the parent
	// Endpoint's own IdentityContext (both are stamped from the same
	// source, at the same point, in
	// internal/orchestration.Pipeline.crawlAndDiscoverEndpoints), never
	// independently derived.
	IdentityContext string `json:"identity_context,omitempty"`
	// Provenance is Phase 3.18's addition -- see
	// internal/parameters.Provenance for the full rationale. Always
	// "REQUEST_INPUT" for every Parameter row discovered before Phase
	// 3.18 (the migration backfills existing rows to this value via
	// the column's own DEFAULT -- the factually correct backfill, not
	// a placeholder: every one of them WAS discovered the way this
	// value now means). "RESPONSE_FIELD" marks a field only ever
	// OBSERVED in a response body -- never automatically a confirmed,
	// writable request input (task section 18's explicit distinction).
	Provenance string `json:"provenance,omitempty"`
	// Hidden is Phase 3.21's own addition: true iff this field's
	// original HTML input carried type="hidden" -- "" (false) for
	// every non-form-discovered Parameter (query, JSON, path) and for
	// every row that existed before this field. Answers "was this
	// field hidden" directly, without inventing a Classification value
	// (see docs/phase-3-21-form-mutation.md section 2). Distinct from
	// "is this a likely CSRF/security token" (parameters.IsLikelySecurityToken,
	// a pure function over Name, not a stored column) -- a field can be
	// hidden without being a security token, and vice versa (rare, but
	// possible for a non-hidden anti-CSRF field rendered as a visible
	// input in some frameworks).
	Hidden bool `json:"hidden,omitempty"`
	// PathSegmentIndex is Phase 3.23's own addition: the 0-based path
	// segment mutation.applyPath must replace, meaningful only when
	// Location == "path". -1 for every other Parameter, and for every
	// row that existed before this field (never 0, which is a genuine,
	// valid segment index) -- see docs/phase-3-23-path-parameters.md
	// section 1.3.
	PathSegmentIndex int       `json:"path_segment_index,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// Vulnerability is a class of weakness a detection module can identify,
// reserved for the detection stage (not populated in Phase 1).
type Vulnerability struct {
	ID          string    `json:"id"`
	ScanJobID   string    `json:"scan_job_id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// EvidenceKind identifies the shape of an Evidence record's payload.
type EvidenceKind string

const (
	EvidenceKindRequestResponse EvidenceKind = "request_response"
	EvidenceKindScreenshot      EvidenceKind = "screenshot"
	EvidenceKindText            EvidenceKind = "text"

	// EvidenceKindBaseline identifies an evidence record describing a
	// detector's own CONTROL request/response -- the unmodified or
	// reference exchange it compares its probe(s) against internally,
	// captured as its own record rather than discarded once that
	// comparison is made. Added in Phase 3.11 so real, already-computed
	// baseline data (several detectors already hold one in memory; see
	// docs/phase-3-11-scan-orchestrator.md "Real evidence integration")
	// survives into a Finding's Evidence instead of being thrown away.
	EvidenceKindBaseline EvidenceKind = "baseline"

	// EvidenceKindProbe identifies an evidence record describing an
	// ADDITIONAL probe a detector already issued and evaluated beyond
	// the one it folded into its main EvidenceKindRequestResponse item
	// -- e.g. a second cross-authorization-context attempt (idor) or a
	// second traversal payload variant (traversal) that was already
	// computed but previously discarded. Added in Phase 3.11 alongside
	// EvidenceKindBaseline; see docs/phase-3-11-scan-orchestrator.md
	// "Real evidence integration."
	EvidenceKindProbe EvidenceKind = "probe"
)

// Evidence is a stored artifact supporting a Finding, reserved for the
// evidence collection stage (not populated in Phase 1).
type Evidence struct {
	ID        string       `json:"id"`
	FindingID string       `json:"finding_id"`
	Kind      EvidenceKind `json:"kind"`
	Content   string       `json:"content"`
	CreatedAt time.Time    `json:"created_at"`
}

// Severity is a Finding's assessed impact level.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ValidationStatus tracks whether a Finding's existence has been confirmed.
type ValidationStatus string

const (
	ValidationStatusUnvalidated   ValidationStatus = "unvalidated"
	ValidationStatusConfirmed     ValidationStatus = "confirmed"
	ValidationStatusFalsePositive ValidationStatus = "false_positive"
)

// Finding is a reported issue, produced by the detection/validation
// stages (not populated until Phase 3.1's detection engine, but modeled
// since `scanner findings` and `scanner report` read from this shape).
//
// DetectorID/Host/Port/URL/Method were added in Phase 3.1
// (internal/detection) alongside the fields already modeled since
// Phase 1 planning -- AffectedEndpoint/AffectedParameter continue to
// hold a path-only endpoint and its parameter name (matching how
// lab's Phase 3 ground truth already keys on them), while URL
// holds the full request URL a detector actually probed, and
// Host/Port/Method give a report or CLI table the pieces to display
// without re-parsing URL. Source names what produced the finding
// ("sakanner" for the built-in detection engine, or an external tool's
// name once one exists) -- the same convention Technology.Source
// already established. ValidationStatus doubles as the finding's
// lifecycle status field.
type Finding struct {
	ID                string           `json:"id"`
	ScanID            string           `json:"scan_id"`
	DetectorID        string           `json:"detector_id,omitempty"`
	Target            string           `json:"target"`
	Asset             string           `json:"asset,omitempty"`
	VulnerabilityType string           `json:"vulnerability_type"`
	Title             string           `json:"title"`
	Description       string           `json:"description"`
	Severity          Severity         `json:"severity"`
	Confidence        float64          `json:"confidence"`
	Host              string           `json:"host,omitempty"`
	Port              int              `json:"port,omitempty"`
	URL               string           `json:"url,omitempty"`
	Method            string           `json:"method,omitempty"`
	AffectedEndpoint  string           `json:"affected_endpoint,omitempty"`
	AffectedParameter string           `json:"affected_parameter,omitempty"`
	DetectionMethod   string           `json:"detection_method,omitempty"`
	ValidationStatus  ValidationStatus `json:"validation_status"`
	Evidence          []Evidence       `json:"evidence,omitempty"`
	Remediation       string           `json:"remediation,omitempty"`
	References        []string         `json:"references,omitempty"`
	Source            string           `json:"source,omitempty"`
	// IdentityContext is Phase 3.19's own addition: the configured
	// IDENTITY name (e.g. "account-a") whose authenticated session
	// produced the request this finding is based on, copied verbatim
	// from the Target this finding was detected against (see
	// internal/detection.normalizeFinding) -- never set directly by a
	// detector. "" for an unauthenticated scan or a bare
	// --auth-profile scan with no identity wrapper, exactly mirroring
	// Endpoint.IdentityContext/Parameter.IdentityContext's own,
	// established convention.
	IdentityContext string    `json:"identity_context,omitempty"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}
