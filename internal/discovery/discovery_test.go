package discovery

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"sakanner/internal/dns"
)

func TestEnumerate_ReturnsResolvingCandidates(t *testing.T) {
	resolver := dns.NewFakeResolver()
	resolver.Hosts["www.example.com"] = []net.IP{net.ParseIP("203.0.113.1")}
	resolver.Hosts["api.example.com"] = []net.IP{net.ParseIP("203.0.113.2")}
	// "dev.example.com" intentionally not registered -> does not resolve.

	e := NewWordlistEnumerator([]string{"www", "api", "dev"}, resolver, 4)

	out := make(chan Candidate, 10)
	if err := e.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	close(out)

	var names []string
	for c := range out {
		names = append(names, c.Name)
		if c.Source != "wordlist" {
			t.Errorf("Source = %q, want wordlist", c.Source)
		}
	}
	sort.Strings(names)

	want := []string{"api.example.com", "www.example.com"}
	if len(names) != len(want) {
		t.Fatalf("got names %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestEnumerate_EmptyWordlist(t *testing.T) {
	resolver := dns.NewFakeResolver()
	e := NewWordlistEnumerator(nil, resolver, 4)

	out := make(chan Candidate, 1)
	if err := e.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	close(out)

	if _, ok := <-out; ok {
		t.Error("expected no candidates for empty wordlist")
	}
}

func TestEnumerate_ContextCancellation(t *testing.T) {
	resolver := dns.NewFakeResolver()
	for i := 0; i < 100; i++ {
		resolver.Hosts[wordAt(i)+".example.com"] = []net.IP{net.ParseIP("203.0.113.1")}
	}
	words := make([]string, 100)
	for i := range words {
		words[i] = wordAt(i)
	}

	e := NewWordlistEnumerator(words, resolver, 4)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	out := make(chan Candidate, 100)
	done := make(chan error, 1)
	go func() { done <- e.Enumerate(ctx, "example.com", out) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enumerate did not return promptly after context cancellation")
	}
}

func wordAt(i int) string {
	return "w" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
}
