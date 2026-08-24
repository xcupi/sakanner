package detection

import (
	"context"
	"net"

	"sakanner/pkg/models"
)

// TargetKind identifies the shape of recon data a Target was built
// from, and is what a Detector's Metadata declares it can ever be
// eligible for -- the engine uses it as the first, cheap filter before
// calling Detector.Eligible on any specific Target.
type TargetKind string

const (
	// TargetKindHTTPService is one probed HTTP(S) service as a whole
	// (its base URL, headers, status code, fingerprinted technologies) --
	// what a detector that inspects service-level behavior (missing
	// security headers, CORS configuration, exposed admin paths, known
	// vulnerable components) operates on.
	TargetKindHTTPService TargetKind = "http_service"

	// TargetKindEndpoint is one discovered URL (path + method) on an
	// HTTPService, optionally naming a single parameter to test -- what
	// a detector that probes a specific input (reflected/stored XSS,
	// SQL injection, path traversal, open redirect) operates on.
	TargetKindEndpoint TargetKind = "endpoint"
)

// Target is the normalized view of Phase 2 recon output the engine
// passes to a detector for one detection attempt. It is a value copy,
// never a pointer into storage rows or into another Target -- a
// detector cannot mutate what other detectors or the engine itself see.
type Target struct {
	Kind TargetKind

	ScanJobID     string
	HTTPServiceID string
	EndpointID    string // "" unless Kind == TargetKindEndpoint

	// Host/IP/Port/Scheme are exactly what a detector must dial through
	// Executor.Do -- IP is the SAME scope-validated address Phase 2
	// already resolved and probed, never re-resolved here (the same
	// resolve-once discipline internal/http and internal/crawler follow
	// -- see docs/phase-3-1-detection-engine.md "Scope enforcement").
	Host   string
	IP     net.IP
	Port   int
	Scheme string

	// URL is the full request URL for this target (the HTTPService's
	// base URL, or that URL with Path substituted, for an endpoint
	// target). Path is URL's path component alone, matching how
	// AffectedEndpoint has always been recorded (see
	// pkg/models.Finding's doc comment).
	URL  string
	Path string

	// Method/Parameter/ParameterLocation are set only for
	// TargetKindEndpoint targets that name a specific input to test.
	// ParameterLocation is one of "query"/"form"/"body"/"path"/"header"/
	// "cookie" ("form", Phase 3.21, is a POST/non-GET form-urlencoded
	// body parameter -- distinct from "body", which means a JSON body
	// parameter; "path", Phase 3.23, is a URL path segment; all trace
	// back to pkg/models.Parameter.Location's existing convention).
	Method            string
	Parameter         string
	ParameterLocation string

	// PathSegmentIndex is Phase 3.23's own addition: the 0-based path
	// segment mutation.NewPathMutation must target, meaningful only
	// when ParameterLocation == "path" (copied verbatim from
	// models.Parameter.PathSegmentIndex, which is -1 for every other
	// Parameter). See docs/phase-3-23-path-parameters.md section 1.3.
	PathSegmentIndex int

	// FormFields is Phase 3.21's own addition: the OTHER already-
	// discovered field values of the SAME form this Target's own
	// Parameter belongs to (never including this Target's own
	// Parameter's payload -- Mutate overwrites that one regardless), so
	// NewMutationRequest can seed a baseline request that already looks
	// like a complete, real form submission instead of one containing
	// only the single field being targeted. nil for every Target this
	// does not apply to (query/JSON from a non-form source, path,
	// header, cookie, HTTPService-level) -- zero behavior change for
	// them. See docs/phase-3-21-form-mutation.md section 3.
	FormFields map[string]string

	// Technologies are the fingerprinted Technology rows already
	// recorded for this target's HTTPService, handed to the detector
	// directly so a component-version detector needs no second Store
	// round trip.
	Technologies []models.Technology

	// IdentityContext is Phase 3.16's own addition -- the configured
	// IDENTITY name (e.g. "account-a") whose authenticated session
	// discovered this target, copied verbatim from the Endpoint/
	// Parameter row it was built from ("" for an HTTPService-level
	// target, an unauthenticated one, or one authenticated via a bare
	// --auth-profile with no identity wrapper). This is the
	// "authorization-context model" task section 15 asks for: a future
	// detector can read Target.IdentityContext to know which identity
	// made this request WITHOUT ever touching a Session, a Profile, or
	// any credential -- this package has no such access to begin with
	// (BuildTargets reads only already-persisted, already-redacted
	// Endpoint/Parameter rows, never internal/auth at all). No detector
	// in this codebase currently branches on this field -- task's
	// explicit "do not implement the authorization detector itself."
	IdentityContext string
}

// Outcome classifies what a Detector's Detect call produced. "Not
// vulnerable" (OutcomeNoFinding) is success, not an error -- see
// Detector's doc comment.
type Outcome string

const (
	OutcomeNoFinding Outcome = "no_finding"
	OutcomeFinding   Outcome = "finding"
	// OutcomeSkipped means the detector determined, only once actually
	// running against this specific Target, that it does not apply --
	// e.g. a required response shape wasn't present. This should be
	// rare: Detector.Eligible is meant to catch this cheaply beforehand
	// without ever calling Detect. It is still distinct from an error:
	// the detector functioned correctly and made a decision, it just
	// didn't test this particular target.
	OutcomeSkipped Outcome = "skipped"
)

// Result is what Detect returns. Findings is usually 0 or 1 entries
// (matching Outcome), but a detector MAY report more than one finding
// from a single Detect call (e.g. one per payload variant that each
// independently confirmed the vulnerability).
type Result struct {
	Outcome  Outcome
	Findings []models.Finding
}

// Metadata is a detector's static, declarative identity -- read by the
// Registry and the CLI, and by the engine's cheap pre-filter before
// Detect is ever called. It never itself drives detection logic; that
// is entirely Detector.Eligible/Detect's job.
type Metadata struct {
	// ID is stable and unique across the whole registry (kebab-case,
	// e.g. "reflected-xss") -- Registry.Register rejects a duplicate.
	ID       string
	Name     string
	Category string // free-text vulnerability class, e.g. "injection"

	// SupportedTargetTypes lists every TargetKind this detector could
	// ever be eligible for. The engine skips calling Eligible at all for
	// a Target whose Kind isn't listed here.
	SupportedTargetTypes []TargetKind

	// SupportedMethods restricts eligibility to endpoint targets whose
	// Method is in this list; empty means "any method." Ignored for
	// target kinds other than TargetKindEndpoint.
	SupportedMethods []string

	// Prerequisites documents pipeline capabilities this detector needs
	// that Phase 2's recon may not yet provide (e.g. "authenticated
	// differential probing") -- purely informational, mirroring
	// lab/ground-truth-vulnerabilities.yaml's requires_capability
	// field, so `scanner detectors list` can show why a registered
	// detector might still never produce a finding.
	Prerequisites []string

	DefaultSeverity models.Severity
}

// Detector is the minimal contract every vulnerability detector
// implements. See docs/phase-3-1-detection-engine.md "How to implement
// a new detector" for the full guide -- adding one never requires
// modifying Registry, Engine, Executor, or any other file in this
// package.
type Detector interface {
	Metadata() Metadata

	// Eligible reports whether t is a plausible candidate for this
	// detector -- fast, no network I/O, called for every target the
	// engine's cheap Metadata-based pre-filter already passed. This is
	// where a detector encodes any finer eligibility logic Metadata
	// can't express declaratively (e.g. "the endpoint's path looks like
	// it takes a numeric ID parameter").
	Eligible(t Target) bool

	// Detect performs the actual detection logic against t, using x to
	// make any HTTP request -- x is the ONLY sanctioned way to reach a
	// target; see Executor's doc comment for why a detector must never
	// build its own http.Client. Returning (Result{Outcome:
	// OutcomeNoFinding}, nil) means "checked, not vulnerable" -- that is
	// success, not an error. A non-nil error means the detector itself
	// failed (a request error, an unexpected response shape it can't
	// interpret) and is recorded by the engine as a detector error,
	// distinct from both a finding and a clean no-finding result, and
	// never aborts the rest of the scan.
	Detect(ctx context.Context, t Target, x *Executor) (Result, error)
}
