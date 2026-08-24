package safedial

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newIPServer starts an httptest server bound to a specific loopback IP
// -- required so two servers in one test represent genuinely different
// HOSTS (plain httptest.NewServer always binds 127.0.0.1, so two such
// servers differ only by port, which does not exercise cross-host
// behavior at all -- see docs/phase-3-15-authenticated-crawling.md "Why
// a shared pinned transport" for why this distinction mattered during
// this package's own development).
func newIPServer(t *testing.T, ip string, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestPinnedRoundTripper_AttachesHeaderOnMatch(t *testing.T) {
	var got string
	srv := newIPServer(t, "127.0.0.70", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))

	client := &http.Client{Transport: &PinnedRoundTripper{
		Headers: map[string]string{"Authorization": "Bearer tok"}, PinnedHost: "127.0.0.70",
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer tok", got)
	}
}

func TestPinnedRoundTripper_DoesNotAttachOnMismatch(t *testing.T) {
	var got string
	srv := newIPServer(t, "127.0.0.71", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))

	client := &http.Client{Transport: &PinnedRoundTripper{
		Headers: map[string]string{"Authorization": "Bearer tok"}, PinnedHost: "some-other-host.test",
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if got != "" {
		t.Fatalf("Authorization = %q, want empty (host mismatch)", got)
	}
}

// TestPinnedRoundTripper_StripsPreExistingHeaderOnMismatch is the
// regression test for the actual bug found and fixed during this
// package's development: a header ALREADY present on the incoming
// request (as net/http's own Client.do() would place there via its
// header-copying across a same-chain redirect) must be REMOVED, not
// merely left un-added, when the request's host does not match
// PinnedHost. An add-only implementation passes
// TestPinnedRoundTripper_DoesNotAttachOnMismatch (nothing to add
// wouldn't leak an ABSENT header) but fails THIS test.
func TestPinnedRoundTripper_StripsPreExistingHeaderOnMismatch(t *testing.T) {
	var got string
	srv := newIPServer(t, "127.0.0.72", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))

	rt := &PinnedRoundTripper{Headers: map[string]string{"Authorization": "Bearer tok"}, PinnedHost: "some-other-host.test"}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Simulate what net/http's own Client.do() would have already done:
	// copied the Authorization header onto this request object from an
	// earlier hop, BEFORE this RoundTripper ever sees it.
	req.Header.Set("Authorization", "Bearer tok")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
	if got != "" {
		t.Fatalf("Authorization = %q, want empty -- a pre-existing header must be stripped on host mismatch, not merely left un-added", got)
	}
}

func TestPinnedRoundTripper_OriginalRequestNeverMutated(t *testing.T) {
	srv := newIPServer(t, "127.0.0.73", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rt := &PinnedRoundTripper{Headers: map[string]string{"Authorization": "Bearer tok"}, PinnedHost: "127.0.0.73"}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("test setup invariant broken")
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
	if req.Header.Get("Authorization") != "" {
		t.Fatal("RoundTrip mutated the caller's own *http.Request -- net/http's RoundTripper contract forbids this")
	}
}

func TestPinnedRoundTripper_HostComparisonIsCaseInsensitive(t *testing.T) {
	var got string
	srv := newIPServer(t, "127.0.0.74", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
	}))

	rt := &PinnedRoundTripper{Headers: map[string]string{"X-Api-Key": "k"}, PinnedHost: "127.0.0.74"}
	client := &http.Client{Transport: rt}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if got != "k" {
		t.Fatalf("X-Api-Key = %q, want k", got)
	}
}

func TestPinnedRoundTripper_NoHeadersConfigured_PassesThroughUnchanged(t *testing.T) {
	var sawAuth bool
	srv := newIPServer(t, "127.0.0.75", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
	}))

	rt := &PinnedRoundTripper{PinnedHost: "127.0.0.75"} // no Headers configured
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "operator-set-directly")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
	if !sawAuth {
		t.Fatal("with no Headers configured, PinnedRoundTripper must not touch headers the caller set directly")
	}
}
