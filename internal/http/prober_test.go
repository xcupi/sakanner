package http

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// hostValidator allows only explicitly listed hostnames (checked by
// CheckHost, used for redirect targets) and IPs (checked by CheckIP,
// used for direct dials), for precise control in tests.
type hostValidator struct {
	allowedHosts map[string]bool
	allowedIPs   map[string]bool
}

func (v *hostValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	if v.allowedHosts[host] {
		return scope.Decision{Allowed: true}, nil
	}
	return scope.Decision{Allowed: false, Reason: "not in allowlist"}, nil
}

func (v *hostValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	if v.allowedIPs[ip.String()] {
		return scope.Decision{Allowed: true}, nil
	}
	return scope.Decision{Allowed: false, Reason: "not in allowlist"}, nil
}

func (v *hostValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	if d, _ := v.CheckHost(ctx, hostname); d.Allowed {
		return d, nil
	}
	return v.CheckIP(ctx, ip)
}

func testServerIPPort(t *testing.T, srv *httptest.Server) (net.IP, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("could not parse listener IP %q", host)
	}
	return ip, port
}

func TestProbe_PlainHTTP(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Server", "test-server")
		w.Write([]byte("<html><head><title>Hello World</title></head><body></body></html>"))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 5 * time.Second, MaxRedirects: 3}, nil)

	svc, _, err := p.Probe(context.Background(), ip, port, ip.String())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if svc.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", svc.StatusCode)
	}
	if svc.Title != "Hello World" {
		t.Errorf("Title = %q, want %q", svc.Title, "Hello World")
	}
	if svc.Headers["Server"] != "test-server" {
		t.Errorf("Headers[Server] = %q, want test-server", svc.Headers["Server"])
	}
}

func TestProbe_HTTPS_CapturesCert(t *testing.T) {
	srv := httptest.NewTLSServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	v := &hostValidator{allowedIPs: map[string]bool{ip.String(): true}}
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 5 * time.Second, MaxRedirects: 3}, nil)

	svc, _, err := p.Probe(context.Background(), ip, port, ip.String())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if svc.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", svc.Scheme)
	}
	if svc.TLSSubject == "" {
		t.Errorf("expected TLSSubject to be captured despite self-signed/untrusted cert")
	}
	if svc.TLSVersion == "" {
		t.Errorf("expected TLSVersion to be captured")
	}
	if !svc.TLSSelfSigned {
		t.Errorf("expected TLSSelfSigned = true for httptest's self-signed certificate")
	}
}

// TestProbe_HTTPToHTTPSRedirect_SchemeReflectsFinalResponse is a
// regression test for a real bug found during Phase 2 acceptance
// testing: a port that speaks plain HTTP but immediately redirects to
// HTTPS was recorded with Scheme="http" even though URL and every TLS*
// field described the final https:// response -- self-contradictory to
// a report reader. Scheme must track the same final state URL does.
func TestProbe_HTTPToHTTPSRedirect_SchemeReflectsFinalResponse(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("secure"))
	}))
	defer tlsSrv.Close()
	tlsIP, tlsPort := testServerIPPort(t, tlsSrv)

	httpSrv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, fmt.Sprintf("https://%s:%d/", tlsIP, tlsPort), nethttp.StatusMovedPermanently)
	}))
	defer httpSrv.Close()
	httpIP, httpPort := testServerIPPort(t, httpSrv)

	// CheckRedirect validates each hop via CheckHost (not CheckIP), so
	// the redirect target's host string must be allow-listed there too,
	// not just its IP.
	v := &hostValidator{
		allowedIPs:   map[string]bool{httpIP.String(): true, tlsIP.String(): true},
		allowedHosts: map[string]bool{httpIP.String(): true, tlsIP.String(): true},
	}
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 5 * time.Second, MaxRedirects: 3}, nil)

	svc, _, err := p.Probe(context.Background(), httpIP, httpPort, httpIP.String())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !strings.HasPrefix(svc.URL, "https://") {
		t.Fatalf("URL = %q, want an https:// URL after following the redirect", svc.URL)
	}
	if svc.Scheme != "https" {
		t.Errorf("Scheme = %q, want https (must match URL's own scheme, not the scheme this probe started with)", svc.Scheme)
	}
	if svc.TLSSubject == "" {
		t.Errorf("expected TLSSubject to be captured for the final https response")
	}
}

func TestProbe_DeniedIPNeverDials(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		t.Error("handler must not be invoked when the IP is out of scope")
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	v := &hostValidator{} // nothing allowed
	p := NewProber(v, dns.NewFakeResolver(), Config{Timeout: 2 * time.Second, MaxRedirects: 3}, nil)

	if _, _, err := p.Probe(context.Background(), ip, port, ip.String()); err == nil {
		t.Fatal("expected Probe to fail when target IP is out of scope")
	}
}

func TestProbe_RedirectToOutOfScopeHostStopsChain(t *testing.T) {
	// Both test servers necessarily bind to loopback, so scope here is
	// discriminated by hostname (as CheckRedirect does via
	// req.URL.Hostname()), not by IP -- an IP-only check couldn't tell
	// the two servers apart in this test environment.
	var redirectHit bool
	blocked := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		redirectHit = true
		w.Write([]byte("should never be reached"))
	}))
	defer blocked.Close()
	blockedIP, blockedPort := testServerIPPort(t, blocked)

	origin := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "http://evil.test:"+strconv.Itoa(blockedPort)+"/", nethttp.StatusFound)
	}))
	defer origin.Close()
	originIP, originPort := testServerIPPort(t, origin)

	// Only "origin.test" is allowed; "evil.test" (the redirect target) is
	// deliberately excluded to prove CheckRedirect stops the chain before
	// ever dialing it.
	v := &hostValidator{
		allowedHosts: map[string]bool{"origin.test": true},
		allowedIPs:   map[string]bool{originIP.String(): true},
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["evil.test"] = []net.IP{blockedIP}

	p := NewProber(v, resolver, Config{Timeout: 5 * time.Second, MaxRedirects: 3}, nil)

	svc, _, err := p.Probe(context.Background(), originIP, originPort, "origin.test")
	if err != nil {
		t.Fatalf("Probe should still return the last in-scope response, got error: %v", err)
	}
	if svc.StatusCode != nethttp.StatusFound {
		t.Errorf("StatusCode = %d, want %d (redirect response, chain must not continue)", svc.StatusCode, nethttp.StatusFound)
	}
	if redirectHit {
		t.Error("redirect target handler was invoked despite being out of scope -- scope bypass via redirect")
	}
}

func TestProbe_NilIP(t *testing.T) {
	v := &hostValidator{allowedHosts: map[string]bool{}}
	p := NewProber(v, dns.NewFakeResolver(), Config{}, nil)
	if _, _, err := p.Probe(context.Background(), nil, 80, "example.com"); err == nil {
		t.Error("expected error for nil IP")
	}
}
