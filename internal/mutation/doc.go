// Package mutation is Phase 3.17's request mutation & attack surface
// foundation: a canonical HTTP request/response model, deterministic
// cloning, a provenance-carrying parameter-mutation primitive, a
// scope-safe request executor, and a detector-independent response
// comparison primitive.
//
// This package implements no vulnerability detection logic of any
// kind. It never decides that a response "is" a finding, never assigns
// a severity or confidence, and never knows what SQL injection, XSS,
// SSRF, IDOR, or any other vulnerability class looks like -- see
// docs/phase-3-17-request-mutation.md section 0. It exists so a future
// detector can clone/mutate/execute/compare requests without
// reimplementing its own HTTP client, session handling, scope
// enforcement, timeout/cancellation handling, response normalization,
// secret redaction, or concurrency control -- see that document's
// section 15 for the intended call shape.
//
// Request is immutable by convention: every function in this package
// that "changes" a Request (Clone, Mutate) returns a new value; none
// of them ever modify the Request passed in. Execute never mutates the
// Request it is given either.
package mutation
