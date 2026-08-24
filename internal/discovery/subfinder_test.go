package discovery

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"sakanner/internal/dns"
	"sakanner/internal/testutil"
)

func TestSubfinderEnumerator_ResolvesReportedHostsOnly(t *testing.T) {
	binary := testutil.WriteScript(t, "subfinder", `
echo '{"host":"a.example.com"}'
echo 'a stray banner line that is not json'
echo '{"host":"b.example.com"}'
exit 0
`)
	resolver := dns.NewFakeResolver()
	resolver.Hosts["a.example.com"] = []net.IP{net.ParseIP("203.0.113.5")}
	// b.example.com is deliberately left unresolvable.

	e := NewSubfinderEnumerator(binary, resolver, 4)
	if e.Name() != "subfinder" {
		t.Errorf("Name() = %q, want subfinder", e.Name())
	}

	out := make(chan Candidate, 8)
	if err := e.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	close(out)

	var got []Candidate
	for c := range out {
		got = append(got, c)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1 (only the resolvable one): %+v", len(got), got)
	}
	if got[0].Name != "a.example.com" || got[0].Source != "subfinder" {
		t.Errorf("candidate = %+v, want Name=a.example.com Source=subfinder", got[0])
	}
	if len(got[0].IPs) != 1 || got[0].IPs[0] != "203.0.113.5" {
		t.Errorf("candidate IPs = %v, want [203.0.113.5]", got[0].IPs)
	}
}

func TestNewEnumerator_BackendSelection(t *testing.T) {
	resolver := dns.NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewEnumerator("native", nil, resolver, 1, logger)
	if err != nil {
		t.Fatalf("NewEnumerator(native): %v", err)
	}
	if e.Name() != "wordlist" {
		t.Errorf("backend=native: Name() = %q, want wordlist", e.Name())
	}

	if _, err := NewEnumerator("not-a-real-backend", nil, resolver, 1, logger); err == nil {
		t.Error("NewEnumerator(garbage backend) = nil error, want an error")
	}
}

func TestNewEnumerator_AutoFallsBackWhenSubfinderAbsent(t *testing.T) {
	// An empty PATH guarantees Detect can't find "subfinder", regardless
	// of what's actually installed on the machine running this test.
	t.Setenv("PATH", t.TempDir())
	resolver := dns.NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewEnumerator("auto", nil, resolver, 1, logger)
	if err != nil {
		t.Fatalf("NewEnumerator(auto): %v", err)
	}
	if e.Name() != "wordlist" {
		t.Errorf("Name() = %q, want wordlist when subfinder is absent", e.Name())
	}
}

func TestNewEnumerator_AutoUsesSubfinderWhenPresent(t *testing.T) {
	binary := testutil.WriteScript(t, "subfinder", "exit 0\n")
	// Point PATH at exactly the fake binary's directory, so Detect finds
	// this one deterministically regardless of what else is installed.
	t.Setenv("PATH", filepath.Dir(binary))

	resolver := dns.NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewEnumerator("auto", nil, resolver, 1, logger)
	if err != nil {
		t.Fatalf("NewEnumerator(auto): %v", err)
	}
	if e.Name() != "subfinder" {
		t.Errorf("Name() = %q, want subfinder when it's present on PATH", e.Name())
	}
}
