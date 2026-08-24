package mutation

import (
	"net"
	"net/http"
	"net/url"
	"testing"
)

// Note: what were TestNewRequestFromTarget_* tests now live in
// internal/detection (as TestNewMutationRequest_*), alongside the
// NewMutationRequest function itself -- moved there in Phase 3.19 to
// resolve an import cycle (internal/detection now needs
// internal/mutation for Executor.ExecuteMutation; internal/mutation
// must therefore never import internal/detection, including from its
// own tests). See internal/detection/mutation_bridge.go's own doc
// comment for the full rationale.

func TestRequestURL_QueryEncodingDeterministic(t *testing.T) {
	req := Request{Scheme: "http", Host: "app.test", Port: 80, Path: "/x", Query: url.Values{"z": {"1"}, "a": {"2"}, "m": {"3"}}}
	u1 := req.URL().String()
	u2 := req.URL().String()
	if u1 != u2 {
		t.Fatalf("URL() not deterministic across calls: %q vs %q", u1, u2)
	}
	if u1 != "http://app.test:80/x?a=2&m=3&z=1" {
		t.Errorf("unexpected serialization: %q", u1)
	}
}

func TestRequestURL_RawQueryOverrideTakesPrecedence(t *testing.T) {
	raw := "id=1%20OR%201=1"
	req := Request{Scheme: "http", Host: "app.test", Path: "/x", Query: url.Values{"id": {"ignored"}}, RawQueryOverride: &raw}
	if got := req.URL().RawQuery; got != raw {
		t.Errorf("RawQuery = %q, want override %q to take precedence over Query", got, raw)
	}
}

func TestClone_DeepIsolation_MutatingCloneNeverAffectsOriginal(t *testing.T) {
	raw := "orig=1"
	original := Request{
		Query:            url.Values{"a": {"1"}},
		Headers:          http.Header{"X-Test": {"1"}},
		Cookies:          []*http.Cookie{{Name: "sid", Value: "abc"}},
		Body:             []byte("original-body"),
		RawQueryOverride: &raw,
		IP:               net.ParseIP("1.2.3.4"),
	}
	clone := original.Clone()

	clone.Query.Set("a", "MUTATED")
	clone.Query.Set("b", "NEW")
	clone.Headers.Set("X-Test", "MUTATED")
	clone.Headers.Set("X-New", "NEW")
	clone.Cookies[0].Value = "MUTATED"
	clone.Body[0] = 'X'
	*clone.RawQueryOverride = "MUTATED"
	clone.IP[0] = 9

	if original.Query.Get("a") != "1" || original.Query.Get("b") != "" {
		t.Errorf("SECURITY: mutating the clone's Query changed the original: %v", original.Query)
	}
	if original.Headers.Get("X-Test") != "1" || original.Headers.Get("X-New") != "" {
		t.Errorf("SECURITY: mutating the clone's Headers changed the original: %v", original.Headers)
	}
	if original.Cookies[0].Value != "abc" {
		t.Errorf("SECURITY: mutating the clone's Cookie changed the original: %v", original.Cookies[0])
	}
	if string(original.Body) != "original-body" {
		t.Errorf("SECURITY: mutating the clone's Body changed the original: %q", original.Body)
	}
	if *original.RawQueryOverride != "orig=1" {
		t.Errorf("SECURITY: mutating the clone's RawQueryOverride changed the original: %q", *original.RawQueryOverride)
	}
	if !original.IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("SECURITY: mutating the clone's IP changed the original: %v", original.IP)
	}
}

func TestClone_DeepIsolation_MutatingOriginalAfterCloneNeverAffectsClone(t *testing.T) {
	original := Request{Query: url.Values{"a": {"1"}}, Headers: http.Header{"X": {"1"}}, Body: []byte("body")}
	clone := original.Clone()

	original.Query.Set("a", "CHANGED")
	original.Headers.Set("X", "CHANGED")
	original.Body[0] = 'Z'

	if clone.Query.Get("a") != "1" {
		t.Errorf("SECURITY: mutating the original after cloning changed the clone's Query: %v", clone.Query)
	}
	if clone.Headers.Get("X") != "1" {
		t.Errorf("SECURITY: mutating the original after cloning changed the clone's Headers: %v", clone.Headers)
	}
	if string(clone.Body) != "body" {
		t.Errorf("SECURITY: mutating the original after cloning changed the clone's Body: %q", clone.Body)
	}
}

func TestClone_EmptyRequest_NoPanic(t *testing.T) {
	var req Request
	clone := req.Clone()
	if clone.Query == nil || clone.Headers == nil {
		t.Errorf("Clone of a zero-value Request should still yield usable, non-nil Query/Headers: %+v", clone)
	}
}
