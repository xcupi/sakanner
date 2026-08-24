//go:build integration

package dns

import (
	"context"
	"testing"
	"time"
)

// TestLive_LookupHost hits the real DNS system and is excluded from the
// default `go test ./...` run (build tag "integration"). Run explicitly
// with: go test -tags=integration ./internal/dns/...
func TestLive_LookupHost(t *testing.T) {
	r := New(5 * time.Second)
	ips, err := r.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupHost(localhost): %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
}
