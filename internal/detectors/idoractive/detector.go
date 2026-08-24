// Package idoractive implements Phase 3.24's authorization / IDOR-BOLA
// (Insecure Direct Object Reference / Broken Object Level Authorization)
// detector -- the first detector in this codebase to compare TWO
// independently-authenticated identities' access to the same object,
// built entirely on internal/mutation's canonical Request/Mutate/
// Execute model. See docs/phase-3-24-authorization.md for the full
// architecture review.
//
// This is a SECOND, coexisting IDOR/BOLA detector, deliberately not
// replacing internal/detectors/idor (Phase 3.5, still registered but
// disabled -- it never imports internal/mutation and instead builds
// its own private *http.Request per probe). This detector's stable ID
// ("idor-active") is distinct so both can be independently enabled/
// disabled; internal/detectors/idor is not modified by this phase.
//
// Detection only, read-only (GET-only, by construction -- see
// Eligible), one baseline identity (the scan's own primary
// --identity, received the normal way via Detect's own x *Executor
// parameter) plus exactly one compare identity (constructor-supplied,
// mirroring the established ssrf.New(nil)/idor.New(nil)/
// traversal.New(nil) constructor-time-dependency pattern -- see
// docs/phase-3-24-authorization.md section 1.3). A nil compare
// executor makes every Detect call return OutcomeSkipped, exactly like
// those three detectors' own nil-dependency behavior.
package idoractive

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/url"
	"strings"

	"sakanner/internal/detection"
	"sakanner/internal/mutation"
	"sakanner/internal/parameters"
	"sakanner/pkg/models"
)

// ID is this detector's stable registry identifier.
const ID = "idor-active"

// knownBadSentinelValue is a fixed, deterministic, guaranteed-
// synthetic identifier value -- never a guess at a real object ID
// (task's own explicit prohibition). Used only for the known-bad
// control probe (docs/phase-3-24-authorization.md section 3, probe
// 3), issued through the COMPARE identity's own session to establish
// what "this identity does not have this object" looks like.
const knownBadSentinelValue = "999999999"

// maxBodySample bounds how much of a response body this detector
// keeps for evidence/comparison -- matches every other active
// detector's own established bound (mutation.Executor's own
// MaxResponseBodyBytes already enforces this at read time; this is an
// additional, defensive, redundant-by-default bound for consistency).
const maxBodySample = 256 * 1024

// Detector implements detection.Detector for active, mutation-based
// horizontal authorization (IDOR/BOLA) testing.
type Detector struct {
	compareExecutor *detection.Executor
	compareIdentity string
}

// New returns a ready-to-register Detector. compareIdentity is a
// plain, non-secret configured identity NAME (never a credential),
// used only for finding/evidence text and Finding.IdentityContext. A
// nil compareExecutor is safe: Detect always returns OutcomeSkipped
// rather than panicking (see docs/phase-3-24-authorization.md section
// 1.3).
func New(compareExecutor *detection.Executor, compareIdentity string) *Detector {
	return &Detector{compareExecutor: compareExecutor, compareIdentity: compareIdentity}
}

func (Detector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID:                   ID,
		Name:                 "Authorization / IDOR-BOLA Detector (Active)",
		Category:             "broken_access_control",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{nethttp.MethodGet},
		Prerequisites: []string{
			"a second, independently-authenticated identity's *detection.Executor supplied via New() -- see docs/phase-3-24-authorization.md section 6; without one, every Detect call returns OutcomeSkipped",
		},
		DefaultSeverity: models.SeverityCritical,
	}
}

// Eligible implements detection.Detector: a GET-only endpoint target
// (task's own "prefer GET/HEAD/read-only" -- never a method that could
// mutate state under another identity's session, see
// docs/phase-3-24-authorization.md section 17) whose parameter NAME
// looks like an object reference (internal/parameters.
// IsLikelyObjectIdentifier). Every Target this is ever called with
// already came from a REQUEST_INPUT-provenance parameter -- BuildTargets
// never emits a Target for anything else -- so no separate discovery-
// evidence check is needed here (docs/phase-3-24-authorization.md
// section 5). Deliberately does not depend on d.compareExecutor being
// non-nil -- that check belongs in Detect, exactly mirroring
// internal/detectors/idor's own Eligible/Detect split.
func (Detector) Eligible(t detection.Target) bool {
	return t.Kind == detection.TargetKindEndpoint &&
		t.Parameter != "" &&
		t.Method == nethttp.MethodGet &&
		parameters.IsLikelyObjectIdentifier(t.Parameter)
}

// Detect implements detection.Detector. Three probes -- see
// docs/phase-3-24-authorization.md section 3 for the full rationale.
// All requests are built and issued exclusively via
// detection.NewMutationRequest/detection.NewTargetMutation/
// mutation.Mutate/Executor.ExecuteMutation -- the same canonical path
// every active detector since Phase 3.19 uses; no detector-specific
// HTTP client, cookie jar, or scope decision exists anywhere in this
// package.
func (d *Detector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	if d.compareExecutor == nil {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}
	if t.Parameter == "" {
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	}

	objectValue := originalParameterValue(t)
	original := detection.NewMutationRequest(t)

	// Probe 1: baseline -- the EXACT original request, via the BASELINE
	// identity's own executor (x, supplied by the engine the same way
	// every other detector receives it).
	baselineResp, err := x.ExecuteMutation(ctx, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("idoractive: baseline probe: %w", err)
	}
	baselineResp.Body = truncate(baselineResp.Body)
	if !looksLikeSuccessfulObjectResponse(baselineResp) {
		// Not a successful, non-empty, non-login object response -- no
		// reference to compare against. Prefer false negative.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	// Probe 2: cross-test -- the IDENTICAL request (same object value),
	// via the COMPARE identity's own, entirely independent executor.
	crossResp, err := d.compareExecutor.ExecuteMutation(ctx, original)
	if err != nil {
		return detection.Result{}, fmt.Errorf("idoractive: cross-test probe: %w", err)
	}
	crossResp.Body = truncate(crossResp.Body)
	if !looksLikeSuccessfulObjectResponse(crossResp) {
		// Correctly denied (or indistinguishable from denied) -- no
		// evidence of unauthorized access.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	// Probe 3: known-bad control -- same shape, a synthetic sentinel
	// value, still via the COMPARE identity's own executor.
	loc := locationFor(t)
	knownBadMutation := detection.NewTargetMutation(t, loc, knownBadSentinelValue, mutation.EncodingEscaped)
	knownBadReq, err := mutation.Mutate(original, knownBadMutation, mutation.Policy{})
	if err != nil {
		return detection.Result{}, fmt.Errorf("idoractive: known-bad control mutate: %w", err)
	}
	knownBadResp, err := d.compareExecutor.ExecuteMutation(ctx, knownBadReq)
	if err != nil {
		return detection.Result{}, fmt.Errorf("idoractive: known-bad control probe: %w", err)
	}
	knownBadResp.Body = truncate(knownBadResp.Body)

	cmpToBaseline := mutation.Compare(baselineResp, crossResp)
	if cmpToBaseline.StructurallyDifferent {
		// The compare identity's response does not actually match what
		// the baseline identity received for this object -- not
		// evidence of accessing the SAME object.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	cmpToKnownBad := mutation.Compare(knownBadResp, crossResp)
	if !cmpToKnownBad.StructurallyDifferent {
		// The endpoint returns the same shape regardless of which value
		// was requested (a public object, a generic envelope, a
		// constant page) -- never trustworthy evidence of unauthorized
		// access to a SPECIFIC object, no matter how similar it looked
		// to the baseline above.
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}

	echoed := bodyContainsValue(crossResp, objectValue)

	baseline := probeResult{request: original, response: baselineResp}
	crossTest := probeResult{request: original, response: crossResp}
	knownBad := probeResult{request: knownBadReq, response: knownBadResp}

	return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{
		d.finding(t, objectValue, baseline, crossTest, knownBad, knownBadMutation, echoed),
	}}, nil
}

// locationFor maps t.ParameterLocation to the mutation.Location the
// known-bad control's Mutation needs -- identical switch to
// internal/detectors/sqliactive/xssactive's own.
func locationFor(t detection.Target) mutation.Location {
	switch t.ParameterLocation {
	case "form":
		return mutation.LocationForm
	case "body":
		return mutation.LocationJSON
	case "path":
		return mutation.LocationPath
	default:
		return mutation.LocationQuery
	}
}

// originalParameterValue extracts t.Parameter's already-discovered
// value from t, for reporting/echo-evidence purposes only -- the core
// detection logic (baseline/cross-test) never needs this, since both
// simply replay t's own already-complete original request verbatim.
// Best-effort: query and path locations are extracted directly; any
// other location (form/JSON body, neither of which this detector's
// GET-only Eligible gate can realistically ever reach) returns "",
// which only ever lowers the resulting finding's confidence tier
// (docs/phase-3-24-authorization.md section 11), never blocks
// detection.
func originalParameterValue(t detection.Target) string {
	if t.ParameterLocation == "path" {
		segments := strings.Split(strings.Trim(t.Path, "/"), "/")
		if t.PathSegmentIndex >= 0 && t.PathSegmentIndex < len(segments) {
			return segments[t.PathSegmentIndex]
		}
		return ""
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Query().Get(t.Parameter)
}

func truncate(body []byte) []byte {
	if len(body) > maxBodySample {
		return body[:maxBodySample]
	}
	return body
}
