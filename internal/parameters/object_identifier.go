package parameters

import "strings"

// objectIdentifierFieldNames is an exact-match, case-insensitive list of
// common object-reference parameter names -- the task's own worked
// examples (user_id, account_id, order_id, document_id, invoice_id,
// profile_id) plus a few equally common siblings. Deliberately narrow:
// a false negative here just means one genuine object reference is
// never authorization-tested, which is the correct failure direction
// for this phase (see docs/phase-3-24-authorization.md section 8 --
// "prefer false negatives").
var objectIdentifierFieldNames = map[string]bool{
	"id": true, "user_id": true, "account_id": true, "order_id": true,
	"document_id": true, "invoice_id": true, "profile_id": true,
	"customer_id": true, "resource_id": true, "item_id": true, "object_id": true,
}

// nonObjectFieldNames is an exact-match, case-insensitive DENYLIST
// checked BEFORE the allowlist/suffix heuristic below -- pagination,
// version, timestamp, and locale/format/sort parameters that would
// otherwise false-positive against a bare "*_id"/"id" suffix match
// (e.g. "sort_order" ends in a word that could be confused with
// "order_id" if checked carelessly; "order" itself, a sort-direction
// parameter, must never be confused with "order_id", an object
// reference -- see docs/phase-3-24-authorization.md section 8's
// adversarial mapping in section 15).
var nonObjectFieldNames = map[string]bool{
	"page": true, "limit": true, "offset": true, "per_page": true, "size": true,
	"version": true, "v": true, "api_version": true,
	"timestamp": true, "ts": true, "date": true, "time": true,
	"lang": true, "locale": true, "format": true, "sort": true, "order": true, "callback": true,
}

// IsLikelyObjectIdentifier conservatively reports whether name looks
// like a parameter that references a specific, ownable application
// object -- name-based only, never derived from a field's discovered
// VALUE (a value that merely looks numeric/UUID-shaped is not, by
// itself, evidence of an object reference; see
// docs/phase-3-24-authorization.md section 5's identifier-vs-object
// distinction). Used by internal/detectors/idoractive.Eligible to
// decide which already-discovered parameters are worth an
// authorization comparison -- kept here, not in idoractive itself, so
// future improvement of this classification never requires touching
// the detection engine (task section 8's explicit forward-
// compatibility requirement).
func IsLikelyObjectIdentifier(name string) bool {
	trimmed := strings.TrimSpace(name)
	n := strings.ToLower(trimmed)
	if n == "" {
		return false
	}
	if nonObjectFieldNames[n] {
		return false
	}
	if objectIdentifierFieldNames[n] {
		return true
	}
	// snake_case ("resource_id") -- checked on the lowercased form.
	if strings.HasSuffix(n, "_id") {
		return true
	}
	// camelCase ("resourceId") -- checked on the ORIGINAL casing: a
	// capital "I" immediately before a trailing "d" is specifically the
	// camelCase word-boundary marker, unlike a bare case-insensitive
	// "id" suffix, which would also match ordinary words such as
	// "valid", "paid", or "grid" and is deliberately never checked here.
	return strings.HasSuffix(trimmed, "Id")
}
