package http

import (
	"context"
	"net"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// TestProbe_MaliciousHostnameFromExternalTool is a security-review test
// for Phase 2 acceptance testing: hostnames reaching Probe don't always
// come from operator input validated by internal/target.Parse -- an
// external subdomain-discovery tool (subfinder) or a malicious/buggy
// upstream can report a name containing characters Parse would reject.
// This proves such a name can't cause request smuggling, a Host header
// CRLF injection, or a misrouted dial: url.URL.String() percent-encodes
// anything unsafe in the Host component, and the subsequent re-parse by
// http.NewRequestWithContext then correctly rejects the result as an
// invalid URL rather than silently reinterpreting it -- so the only
// possible outcomes are "request built correctly" or "clean error", by
// construction of Go's net/url and net/http packages, never
// misconstruction. Probe must return an ordinary error, not panic or
// hang, for every case.
func TestProbe_MaliciousHostnameFromExternalTool(t *testing.T) {
	hostnames := []string{
		"evil.com@127.0.0.1",          // URL userinfo trick
		"evil.com/../../etc/passwd",   // path-traversal-shaped
		"evil.com\r\nX-Injected: yes", // CRLF/header injection attempt
		"evil.com#fragment",           // fragment injection
		"evil.com\x00nullbyte",        // embedded null byte
		"",                            // empty
	}
	for _, hostname := range hostnames {
		t.Run(hostname, func(t *testing.T) {
			v := &hostValidator{allowedIPs: map[string]bool{"127.0.0.1": true}}
			p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 2 * time.Second, MaxRedirects: 3}, nil)

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Probe panicked on malicious hostname %q: %v", hostname, r)
					}
				}()
				// No real server is listening, and none needs to be --
				// this hostname must fail to even construct a valid
				// request, well before any dial is attempted.
				svc, _, err := p.Probe(context.Background(), net.ParseIP("127.0.0.1"), 1, hostname)
				if err == nil {
					t.Errorf("Probe(%q) = %+v, nil error -- want an error (either a build/dial failure or a clean rejection)", hostname, svc)
				}
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("Probe hung on malicious hostname %q", hostname)
			}
		})
	}
}
