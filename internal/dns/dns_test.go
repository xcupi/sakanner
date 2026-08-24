package dns

import (
	"context"
	"net"
	"testing"
)

func TestFakeResolver_LookupHost(t *testing.T) {
	f := NewFakeResolver()
	f.Hosts["example.com"] = []net.IP{net.ParseIP("203.0.113.5")}

	ips, err := f.LookupHost(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.5")) {
		t.Errorf("LookupHost = %v, want [203.0.113.5]", ips)
	}

	if _, err := f.LookupHost(context.Background(), "unknown.example.com"); err == nil {
		t.Errorf("expected error for unregistered host")
	}
}

func TestFakeResolver_ContextCancelled(t *testing.T) {
	f := NewFakeResolver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := f.LookupHost(ctx, "example.com"); err == nil {
		t.Errorf("expected error from cancelled context")
	}
}

func TestNew_TimeoutWrapping(t *testing.T) {
	// Smoke test only: verify New() returns a usable Resolver and that a
	// zero timeout doesn't panic when composing a context. Live lookups
	// are covered by the integration-tagged test.
	r := New(0)
	if r == nil {
		t.Fatal("New returned nil")
	}
}
