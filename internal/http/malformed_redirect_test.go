package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sakanner/internal/dns"
)

func TestProbe_MalformedLocationHeader(t *testing.T) {
	tests := []string{
		"",                      // empty Location
		"://not-a-valid-url",    // malformed URL
		"http://[invalid-ipv6/", // malformed bracket
		"   ",                   // whitespace only
		"http://\x00evil.com/",  // embedded null byte
	}
	for _, loc := range tests {
		t.Run(loc, func(t *testing.T) {
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				w.Header().Set("Location", loc)
				w.WriteHeader(nethttp.StatusFound)
			}))
			defer srv.Close()
			ip, port := testServerIPPort(t, srv)

			v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
			p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 3 * time.Second, MaxRedirects: 3}, nil)

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Probe panicked on malformed Location %q: %v", loc, r)
					}
				}()
				p.Probe(context.Background(), ip, port, ip.String())
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("Probe hung on malformed Location %q", loc)
			}
		})
	}
}
