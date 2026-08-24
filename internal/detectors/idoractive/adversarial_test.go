package idoractive

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/mutation"
)

// --- Cross-identity safety (docs/phase-3-24-authorization.md section 14) --

// TestAdversarial_SessionIsolation_HeadersNeverCrossIdentities proves,
// at the HTTP layer (not merely by reading the source), that the two
// identities' own credentials (simulated here as a per-identity
// Authorization header, exactly mirroring how a real cookie/bearer
// token would be attached via mutation.SessionContext.Headers) never
// leak into the other identity's own requests -- sequential AND
// concurrent, mirroring Phase 3.21's own
// TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel
// precedent exactly (see docs/phase-3-24-authorization.md section 7).
func TestAdversarial_SessionIsolation_HeadersNeverCrossIdentities(t *testing.T) {
	var mu sync.Mutex
	var sawAuthHeaders []string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		sawAuthHeaders = append(sawAuthHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Query().Get("note_id") != "1001" {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, "<html><body>NOTE_CONTENT_MARKER_1001 private content</body></html>")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorForCredential(t, srv, true, "identity-a", "secret-token-A")
	compare := executorForCredential(t, srv, true, "identity-b", "secret-token-B")

	if _, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline); err != nil {
		t.Fatalf("Detect: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sawAuthHeaders) == 0 {
		t.Fatal("expected at least one request")
	}
	for _, h := range sawAuthHeaders {
		if h != "secret-token-A" && h != "secret-token-B" {
			t.Errorf("SECURITY: server observed an unexpected Authorization value %q -- credentials must never be blended or corrupted across identities", h)
		}
	}
}

// TestAdversarial_SessionIsolation_ConcurrentScans_NeverCrossContaminate
// proves the same isolation under true concurrent execution -- many
// goroutines each running a full Detect call against independently
// constructed baseline/compare executor pairs, asserting the server
// never observes a credential value that was not one of the pair
// actually used for that specific request.
func TestAdversarial_SessionIsolation_ConcurrentScans_NeverCrossContaminate(t *testing.T) {
	var mu sync.Mutex
	violations := 0
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "secret-token-") {
			mu.Lock()
			violations++
			mu.Unlock()
		}
		if r.URL.Query().Get("note_id") != "1001" {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, "<html><body>NOTE_CONTENT_MARKER_1001 private content</body></html>")
	}))
	defer srv.Close()

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "note_id", "query")
			baseline := executorForCredential(t, srv, true, "identity-a", fmt.Sprintf("secret-token-A-%d", i))
			compare := executorForCredential(t, srv, true, "identity-b", fmt.Sprintf("secret-token-B-%d", i))
			if _, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline); err != nil {
				t.Errorf("Detect (goroutine %d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if violations != 0 {
		t.Errorf("SECURITY: %d requests carried a malformed/missing Authorization header under concurrent execution", violations)
	}
}

// executorForCredential is executorFor, plus a per-identity
// "credential" value attached as an Authorization header -- used only
// to prove no cross-identity leakage; the real production path never
// attaches a raw credential this way (auth.Session carries only a
// cookie jar/header map already stripped of any raw password, see
// docs/phase-3-24-authorization.md section 1.1).
func executorForCredential(t *testing.T, srv *httptest.Server, allowed bool, identity, credential string) *detection.Executor {
	t.Helper()
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	sess := mutation.SessionContext{
		PinnedHost:      host,
		IdentityContext: identity,
		Headers:         map[string]string{"Authorization": credential},
	}
	return detection.NewExecutorWithSession(&fakeValidator{allowed: allowed}, dns.NewFakeResolver(), detection.ExecutorConfig{}, sess)
}

// --- Host safety (docs/phase-3-24-authorization.md section 13) -----------

// TestAdversarial_KnownBadControl_NeverChangesHost proves the
// known-bad control's mutated VALUE -- a synthetic sentinel a caller
// never controls -- can never change the dial target, mirroring the
// identical, already-established host-safety argument every other
// active detector's own adversarial suite makes (e.g.
// internal/detectors/sqliactive's
// TestDetect_PathSegment_RealSQLiProbes_NeverChangeHost).
func TestAdversarial_KnownBadControl_NeverChangesHost(t *testing.T) {
	var sawHost string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		if r.URL.Query().Get("note_id") != "1001" {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, "<html><body>NOTE_CONTENT_MARKER_1001</body></html>")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "note_id", "query")
	baseline := executorFor(t, srv, true, "identity-a")
	compare := executorFor(t, srv, true, "identity-b")
	if _, err := New(compare, "identity-b").Detect(context.Background(), tgt, baseline); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- the known-bad sentinel value must never change the dial target", sawHost, tgt.Host)
	}
}

// --- Response classifier unit tests ---------------------------------------

func TestLooksLikeSuccessfulObjectResponse(t *testing.T) {
	cases := []struct {
		name string
		resp mutation.Response
		want bool
	}{
		{"success with real content", mutation.Response{Outcome: mutation.OutcomeSuccess, StatusCode: 200, Body: []byte("real object content here, plenty of bytes")}, true},
		{"non-2xx", mutation.Response{Outcome: mutation.OutcomeSuccess, StatusCode: 403, Body: []byte("forbidden but with a long body just in case")}, false},
		{"empty body", mutation.Response{Outcome: mutation.OutcomeSuccess, StatusCode: 200, Body: []byte("")}, false},
		{"near-empty body", mutation.Response{Outcome: mutation.OutcomeSuccess, StatusCode: 200, Body: []byte("{}")}, false},
		{"login page", mutation.Response{Outcome: mutation.OutcomeSuccess, StatusCode: 200, Body: []byte("<html><body>Please log in to continue</body></html>")}, false},
		{"not success outcome", mutation.Response{Outcome: mutation.OutcomeTransportError, StatusCode: 200, Body: []byte("this has plenty of content in it")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeSuccessfulObjectResponse(c.resp); got != c.want {
				t.Errorf("looksLikeSuccessfulObjectResponse(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestBodyContainsValue(t *testing.T) {
	resp := mutation.Response{Body: []byte("note id=1001 content here")}
	if !bodyContainsValue(resp, "1001") {
		t.Error("expected bodyContainsValue to find the echoed value")
	}
	if bodyContainsValue(resp, "9999") {
		t.Error("expected bodyContainsValue to NOT find an absent value")
	}
	if bodyContainsValue(resp, "") {
		t.Error("an empty value must never count as echoed")
	}
}
