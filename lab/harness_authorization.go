// Phase 3.24 Authorization / IDOR-BOLA test fixtures. Reuses
// harness_auth.go's own authApp/requireSession/userIDFor session
// infrastructure unchanged -- no second account/session system, and
// the SAME two accounts Phase 3.16 already established (Account A =
// AccountAUserID 1001, Account B = AccountBUserID 1002). See
// docs/phase-3-24-authorization.md section 16.
//
// Five endpoints, mirroring the task's own required lab scenarios:
//
//   - /notes?note_id=<id>      VULNERABLE -- no ownership check at
//     all; the primary horizontal-authorization-failure proof object.
//   - /documents?doc_id=<id>   SAFE -- a genuine ownership check, 403s
//     a cross-identity request.
//   - /shared?share_id=<id>    intentionally accessible to BOTH
//     accounts by design -- see this file's own doc comment below for
//     why this is a KNOWN, understood limitation, not a bug in
//     internal/detectors/idoractive.
//   - /ping?request_id=<id>    a constant response regardless of
//     value -- proves the known-bad-control mechanism correctly
//     suppresses a finding when an endpoint is not identity/object-
//     sensitive at all.
//   - /archive?page=<n>        a plainly non-object, pagination-shaped
//     parameter -- proves internal/parameters.IsLikelyObjectIdentifier's
//     name-based exclusion, not runtime detector logic, is what keeps
//     this out of authorization testing entirely.
//
// No vulnerability is introduced into any production sakanner code by
// this file -- it is lab-only, physically under lab/, exactly like
// every other fixture file in this package.
package lab

import (
	"fmt"
	"net/http"
	"strconv"
)

// NoteAID/DocAID/SharedID are this file's own deterministic object
// identifiers -- Account A's note, Account A's document, and the one
// object both accounts may legitimately access, respectively.
const (
	NoteAID  = 5001
	DocAID   = 6001
	SharedID = 7001
)

// noteOwner/docOwner are this fixture's server-side ground truth --
// which account owns which object -- exactly mirroring how
// internal/detectors/idor's own AuthContext.OwnsResourceIDs works,
// just fixed in the lab server instead of client-configured. Neither
// map is consulted by /notes (the vulnerable endpoint deliberately
// never checks ownership); only /documents (the safe endpoint) does.
var noteOwner = map[int]string{NoteAID: AccountAUsername}
var docOwner = map[int]string{DocAID: AccountAUsername}

// registerAuthorizationFixtures adds this file's five routes onto
// authApp's existing mux -- called once from authApp.handler(),
// mirroring lab/harness_path_parameters.go's own
// registerPathParameters(mux) precedent (Phase 3.23).
func registerAuthorizationFixtures(a *authApp, mux *http.ServeMux) {
	// /notes?note_id=<id> -- VULNERABLE: returns the note's content for
	// ANY note_id, regardless of the caller's own identity. No
	// ownership check exists anywhere in this handler.
	mux.HandleFunc("/notes", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		id, err := strconv.Atoi(r.URL.Query().Get("note_id"))
		owner, ok := noteOwner[id]
		if err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "note not found")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Note %d (owned by %s): NOTE_CONTENT_MARKER_%d -- this is private note content that should only ever be visible to its own owner.</body></html>", id, owner, id)
	}))

	// /documents?doc_id=<id> -- SAFE: verifies the caller's own
	// identity owns doc_id before returning anything -- proves
	// idoractive does NOT flag a correctly-defended endpoint.
	mux.HandleFunc("/documents", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		id, err := strconv.Atoi(r.URL.Query().Get("doc_id"))
		owner, ok := docOwner[id]
		if err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "document not found")
			return
		}
		if owner != username {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "forbidden: you do not own this document")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Document %d (owned by %s): DOCUMENT_CONTENT_MARKER_%d</body></html>", id, owner, id)
	}))

	// /shared?share_id=<id> -- intentionally accessible to BOTH Account
	// A and Account B by design (a genuine collaborative object, not a
	// bug). This is a deliberate, HONEST demonstration of a known,
	// accepted limitation shared by every dynamic BOLA-testing tool
	// (see docs/phase-3-24-authorization.md section 15): response-
	// comparison-only IDOR detection cannot distinguish "this specific
	// object is legitimately shared with this specific other identity"
	// from "this is a genuine authorization failure" using response
	// content alone -- both look identical from outside. Only an
	// unauthenticated OR structurally-generic-regardless-of-value
	// response (see /ping below) is distinguishable, and this endpoint
	// is neither: it still requires authentication, and it still 404s
	// a bogus/nonexistent share_id, so a correctly-implemented
	// detector applying this phase's own three-probe design MAY still
	// produce a finding here -- expected, understood, and explicitly
	// documented in docs/phase-3-24-acceptance-test.md, not silently
	// hidden.
	mux.HandleFunc("/shared", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		id, err := strconv.Atoi(r.URL.Query().Get("share_id"))
		if err != nil || id != SharedID {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "shared object not found")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Shared object %d: SHARED_CONTENT_MARKER -- accessible to every authenticated account by design.</body></html>", id)
	}))

	// /ping?request_id=<id> -- a generic, constant response regardless
	// of request_id's value or the caller's identity -- proves
	// idoractive's known-bad-control mechanism correctly suppresses a
	// finding when the endpoint is not actually identity- or object-
	// sensitive at all (task's "same response for every object" /
	// "generic API envelope" adversarial cases).
	mux.HandleFunc("/ping", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))

	// /archive?page=<n> -- a plainly non-object, pagination-shaped
	// parameter -- proves internal/parameters.IsLikelyObjectIdentifier's
	// own name-based exclusion, not idoractive's runtime logic, is
	// what keeps this out of authorization testing entirely (Eligible
	// returns false before any request is ever issued).
	mux.HandleFunc("/archive", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>archive page -- ARCHIVE_MARKER</body></html>")
	}))
}
