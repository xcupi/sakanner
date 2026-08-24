package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// canonicalHashInput is the EXACT set of fields that determine an
// evidence item's identity and integrity hash -- task sections 15-18.
// Deliberately excludes EvidenceID, IntegrityHash (obviously -- the
// hash can't depend on itself), and CollectedAt/Duration (task
// sections 26 and 39 explicitly: "changed timestamp only -> same
// hash"). Every field here is already REDACTED before this struct is
// built (see buildCanonicalEvidence in engine.go), so the hash itself
// never encodes a secret value.
//
// Go's encoding/json marshals struct fields in declaration order and
// sorts map[string]string keys alphabetically -- both deterministic,
// stable properties of the stdlib, not something this package
// reimplements. That is what makes json.Marshal a safe canonical
// serializer here: identical field values always produce identical
// bytes, and field/key ORDER (task section 16's "stable field
// ordering") is never a source of hash instability, including for the
// map-typed fields (Request.Headers, Response.Headers,
// DetectorFields).
type canonicalHashInput struct {
	FindingID      string
	Type           EvidenceType
	Request        RequestEvidence
	Response       ResponseEvidence
	Baseline       *DifferentialEvidence
	Redirect       *RedirectEvidence
	Observation    string
	Verification   string
	Confidence     float64
	DetectorFields map[string]string
}

// canonicalize returns the deterministic byte serialization of e's
// identity-bearing fields -- task section 16. Never fails in practice
// (every field is already a plain string/int/float/map of strings),
// but degrades to an empty byte slice rather than panicking if it
// somehow did, so a hash can always be computed.
func canonicalize(input canonicalHashInput) []byte {
	b, err := json.Marshal(input)
	if err != nil {
		return nil
	}
	return b
}

// integrityHash returns the full, hex-encoded SHA-256 over input's
// canonical serialization -- task section 15.
func integrityHash(input canonicalHashInput) string {
	sum := sha256.Sum256(canonicalize(input))
	return hex.EncodeToString(sum[:])
}

// evidenceID derives a stable, deterministic evidence ID from the SAME
// canonical content the integrity hash is computed from -- task
// section 17: "Evidence identity should be based on canonical evidence
// attributes... duplicate evidence must receive the same canonical
// identity." Truncated to 32 hex characters (128 bits), the same
// convention internal/correlation.Identity.FindingID and
// internal/risk's own content-hash IDs already establish in this
// project -- short, fixed-size, and collision-resistant far beyond
// what this system will ever need.
func evidenceID(input canonicalHashInput) string {
	return integrityHash(input)[:32]
}
