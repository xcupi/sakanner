package parameters

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ParseJSONBody discovers top-level and (up to limits.MaxJSONDepth)
// nested JSON object fields from a captured request body -- task's
// input source 10 and the "JSON INPUT DISCOVERY" section. A nested
// field's Name is a deterministic dot-path (e.g. "user.name" for
// {"user":{"name":"alice"}}).
//
// Returned Candidates have EndpointPath/EndpointMethod/EndpointSource
// left unset -- ParseJSONBody has no endpoint context of its own (it
// operates on a raw body only); the caller correlates them to an
// endpoint before persisting, exactly like Normalize's own Candidate
// contract.
//
// Arrays are represented as ONE field (the array as a whole), never
// descended into -- task's explicit "do not flatten arrays
// ambiguously... do not invent semantics that cannot be
// reconstructed." This is a deliberate scope boundary: an array of
// objects' own fields are not individually discoverable in this
// phase.
//
// Malformed JSON never panics or returns an error that aborts a
// caller's larger discovery run -- it returns a Result with no
// Candidates and a Warning describing the parse failure, matching
// task's "do not crash on malformed input."
//
// provenance is stamped onto every returned Candidate verbatim -- see
// Provenance's own doc comment. As of Phase 3.18, this function is
// wired into the live pipeline via NormalizeJSONResponses (see that
// function's doc comment for exactly what it captures and why --
// nothing in this codebase captures a live JSON REQUEST body, only a
// RESPONSE body, so every live caller passes ProvenanceResponseField;
// ProvenanceRequestInput remains available for a direct, non-live
// caller (e.g. a future detector that itself constructs and knows a
// request body) and for this file's own unit tests.
func ParseJSONBody(body []byte, limits Limits, provenance Provenance) Result {
	limits = limits.normalized()

	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return Result{Warnings: []string{fmt.Sprintf("malformed JSON body: %v", err)}}
	}

	obj, ok := v.(map[string]interface{})
	if !ok {
		// A top-level JSON value that isn't an object (an array, a bare
		// string/number/bool, or null) has no named fields to discover
		// -- not an error, simply nothing to report.
		return Result{}
	}

	var candidates []Candidate
	var warnings []string
	fieldCount := 0
	depthLimitHit := false

	var walk func(prefix string, m map[string]interface{}, depth int)
	walk = func(prefix string, m map[string]interface{}, depth int) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic: map iteration order is not stable

		for _, k := range keys {
			if fieldCount >= limits.MaxJSONFields {
				return
			}
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			val := m[k]

			if nested, ok := val.(map[string]interface{}); ok {
				if depth >= limits.MaxJSONDepth {
					depthLimitHit = true
					continue // do not descend further; do not fabricate a value for the remaining nested content
				}
				walk(name, nested, depth+1)
				continue
			}

			candidates = append(candidates, Candidate{
				Name: name, Location: LocationJSON, Value: redactIfSensitive(k, jsonScalarString(val)),
				Source: SourceJSONBody, ContentType: "application/json",
				Provenance: provenance,
			})
			fieldCount++
		}
	}
	walk("", obj, 0)

	if depthLimitHit {
		warnings = append(warnings, fmt.Sprintf("JSON depth limit reached (%d): deeper fields were not discovered", limits.MaxJSONDepth))
	}
	if fieldCount >= limits.MaxJSONFields {
		warnings = append(warnings, fmt.Sprintf("JSON field limit reached (%d): remaining fields were not discovered", limits.MaxJSONFields))
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return Result{Candidates: candidates, Warnings: warnings}
}

// jsonScalarString renders a non-object JSON value (string, number,
// bool, null, or array) as the Candidate.Value string -- arrays are
// rendered via their compact JSON form (never descended into, per this
// file's own doc comment), so the fact that a field IS an array
// remains visible/reconstructable without inventing per-element
// semantics.
func jsonScalarString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
