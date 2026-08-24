// Adversarial tests for the IDOR/BOLA detector, per Phase 3.5's
// explicit adversarial-testing requirement (only ever against
// controlled, synthetic local servers). Several items from that list
// are already covered elsewhere and are not duplicated here:
//   - sequential/random/UUID/invalid IDs -> the detector never reasons
//     about identifier FORM at all (see docs/phase-3-5-idor-bola.md
//     "Resource identifier analysis") -- ownership is a static lookup
//     regardless of what the ID string looks like, so there is nothing
//     ID-shape-specific to test beyond TestDetect_UnconfiguredResourceID_Skipped
//     (detector_test.go), which already exercises an arbitrary
//     unconfigured string
//   - same-user/cross-user/public resources, 403/404, generic 200,
//     missing owner metadata -> detector_test.go
//   - expired/stale token -> TestDetect_ExpiredOrInvalidCredentialContext_NoFinding
//   - duplicate requests -> TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate
//   - out-of-scope resource, cancellation, timeout -> detector_test.go
package idor

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

func TestAdversarial_SequentialIDsAloneNeverImplyIDOR(t *testing.T) {
	// Two sequential numeric IDs, both correctly protected -- the
	// detector must not treat "the IDs are sequential" as evidence of
	// anything; only actual cross-context access matters.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("id")
		caller := r.Header.Get("X-Test-Auth-User")
		owner := map[string]string{"1001": "user-a", "1002": "user-b"}[id]
		w.Header().Set("Content-Type", "application/json")
		if caller != owner {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		fmt.Fprintf(w, `{"id":%q,"owner":%q}`, id, owner)
	}))
	defer srv.Close()

	d := New([]AuthContext{
		{ID: "user-a", Headers: map[string]string{"X-Test-Auth-User": "user-a"}, OwnsResourceIDs: map[string]bool{"1001": true}},
		{ID: "user-b", Headers: map[string]string{"X-Test-Auth-User": "user-b"}, OwnsResourceIDs: map[string]bool{"1002": true}},
	})
	tgt := targetFor(t, srv, "id", "1001")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- sequential numeric IDs, both correctly protected", result.Outcome)
	}
}

func TestAdversarial_UUIDResourceIDsWorkIdentically(t *testing.T) {
	const uuidA = "550e8400-e29b-41d4-a716-446655440000"
	const uuidB = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("id")
		owner := map[string]string{uuidA: "user-a", uuidB: "user-b"}[id]
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"owner":%q}`, id, owner) // no ownership check -- vulnerable, UUID-keyed
	}))
	defer srv.Close()

	d := New([]AuthContext{
		{ID: "user-a", Headers: map[string]string{"X-Test-Auth-User": "user-a"}, OwnsResourceIDs: map[string]bool{uuidA: true}},
		{ID: "user-b", Headers: map[string]string{"X-Test-Auth-User": "user-b"}, OwnsResourceIDs: map[string]bool{uuidB: true}},
	})
	tgt := targetFor(t, srv, "id", uuidA)
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding -- the detector must work identically for UUID-shaped identifiers, not just numeric ones", result.Outcome)
	}
}

func TestAdversarial_MissingOwnerMetadataInResponse_StillEvaluatesOnPresenceOfID(t *testing.T) {
	// The response contains the requested id but no explicit "owner"
	// field at all -- isResourceSpecific only requires the id itself to
	// appear, not a labeled owner field (a real API might not echo
	// ownership metadata at all). This must still work.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("resource_id")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"data":"some content"}`, id) // no "owner" field, no ownership check
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
}

func TestAdversarial_MalformedJSONResponse_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "resource-a", not valid json`)) // deliberately malformed
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	// This detector never parses JSON at all (byte-substring comparison
	// only), so malformed JSON is not special -- this just confirms no
	// panic occurs and a reasonable outcome results.
	if _, err := d.Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestAdversarial_MalformedResourceIDInOriginalURL_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`{"id":"?"}`))
	}))
	defer srv.Close()

	d := New([]AuthContext{ctxA(), ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	tgt.URL = srv.URL + "/?resource_id=" + strings.Repeat("%", 100) // malformed percent-encoding
	x := newExecutor(true, detection.ExecutorConfig{})

	if _, err := d.Detect(context.Background(), tgt, x); err != nil {
		// A clean error is acceptable; a panic is not (proven by this
		// call itself, inside testing.T's own recover).
		t.Logf("Detect returned an error for a malformed URL (acceptable): %v", err)
	}
}

func TestAdversarial_DuplicateResourcesConfiguredToTwoOwners_UsesFirstMatch(t *testing.T) {
	// A misconfiguration (the same resource ID claimed by two
	// contexts) must not panic or behave unpredictably -- ownerOf
	// deterministically returns the first configured match.
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	dup := AuthContext{ID: "user-c", Headers: map[string]string{"X-Test-Auth-User": "user-c"}, OwnsResourceIDs: map[string]bool{"resource-a": true}}
	d := New([]AuthContext{ctxA(), dup, ctxB()})
	tgt := targetFor(t, srv, "resource_id", "resource-a")
	x := newExecutor(true, detection.ExecutorConfig{})

	if _, err := d.Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive(t *testing.T) {
	for _, code := range []int{204, 301, 429, 503} {
		code := code
		t.Run(nethttp.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				w.WriteHeader(code)
				w.Write([]byte(`{"id":"resource-a"}`))
			}))
			defer srv.Close()

			d := New([]AuthContext{ctxA(), ctxB()})
			tgt := targetFor(t, srv, "resource_id", "resource-a")
			x := newExecutor(true, detection.ExecutorConfig{})

			result, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			// None of these are 2xx, so looksAllowed is false for the
			// OWNER's own baseline too -- nothing to compare against.
			if result.Outcome != detection.OutcomeNoFinding {
				t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
			}
		})
	}
}
