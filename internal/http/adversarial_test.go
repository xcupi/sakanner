package http

import (
	"context"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sakanner/internal/dns"
)

// TestProbe_MultiHopRedirect_EveryHopReChecked proves scope is
// re-validated on EVERY redirect hop, not just the first one after the
// original request -- an attacker-controlled site could otherwise pass
// an initial check and then redirect through several in-scope-looking
// hops before finally landing somewhere out of scope.
func TestProbe_MultiHopRedirect_EveryHopReChecked(t *testing.T) {
	var evilHit, midHit int32

	evil := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&evilHit, 1)
		w.Write([]byte("should never be reached"))
	}))
	defer evil.Close()
	evilIP, evilPort := testServerIPPort(t, evil)

	mid := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&midHit, 1)
		nethttp.Redirect(w, r, "http://evil.test:"+strconv.Itoa(evilPort)+"/", nethttp.StatusFound)
	}))
	defer mid.Close()
	midIP, midPort := testServerIPPort(t, mid)

	origin := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "http://mid.test:"+strconv.Itoa(midPort)+"/", nethttp.StatusFound)
	}))
	defer origin.Close()
	originIP, originPort := testServerIPPort(t, origin)

	// origin and mid are in scope; evil deliberately is not.
	v := &hostValidator{
		allowedHosts: map[string]bool{"origin.test": true, "mid.test": true},
		allowedIPs:   map[string]bool{originIP.String(): true},
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["mid.test"] = []net.IP{midIP}
	resolver.Hosts["evil.test"] = []net.IP{evilIP}

	p := NewProber(v, resolver, Config{Timeout: 5 * time.Second, MaxRedirects: 5}, nil)
	svc, _, err := p.Probe(context.Background(), originIP, originPort, "origin.test")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if atomic.LoadInt32(&midHit) != 1 {
		t.Errorf("mid (in-scope hop) was hit %d times, want exactly 1 -- the chain should have followed this far", midHit)
	}
	if atomic.LoadInt32(&evilHit) != 0 {
		t.Errorf("evil (out-of-scope hop) was hit %d times, want 0 -- per-hop scope re-validation failed", evilHit)
	}
	if svc.StatusCode != nethttp.StatusFound {
		t.Errorf("StatusCode = %d, want %d (last in-scope response)", svc.StatusCode, nethttp.StatusFound)
	}
}

// TestProbe_RedirectChain_RecordsIntermediateHops proves the full,
// hop-by-hop redirect chain is captured (not just the final URL), for a
// clean in-scope multi-hop chain.
func TestProbe_RedirectChain_RecordsIntermediateHops(t *testing.T) {
	final := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("landed"))
	}))
	defer final.Close()
	finalIP, finalPort := testServerIPPort(t, final)

	mid := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "http://final.test:"+strconv.Itoa(finalPort)+"/", nethttp.StatusFound)
	}))
	defer mid.Close()
	midIP, midPort := testServerIPPort(t, mid)

	origin := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "http://mid.test:"+strconv.Itoa(midPort)+"/", nethttp.StatusMovedPermanently)
	}))
	defer origin.Close()
	originIP, originPort := testServerIPPort(t, origin)

	v := &hostValidator{
		allowedHosts: map[string]bool{"origin.test": true, "mid.test": true, "final.test": true},
		allowedIPs:   map[string]bool{originIP.String(): true},
	}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["mid.test"] = []net.IP{midIP}
	resolver.Hosts["final.test"] = []net.IP{finalIP}

	p := NewProber(v, resolver, Config{Timeout: 5 * time.Second, MaxRedirects: 5}, nil)
	svc, _, err := p.Probe(context.Background(), originIP, originPort, "origin.test")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if svc.StatusCode != 200 {
		t.Fatalf("StatusCode = %d, want 200 (final landed response)", svc.StatusCode)
	}
	if len(svc.RedirectChain) != 2 {
		t.Fatalf("RedirectChain = %+v, want 2 intermediate hops", svc.RedirectChain)
	}
	if svc.RedirectChain[0].StatusCode != nethttp.StatusMovedPermanently {
		t.Errorf("RedirectChain[0].StatusCode = %d, want %d (origin's redirect)", svc.RedirectChain[0].StatusCode, nethttp.StatusMovedPermanently)
	}
	if svc.RedirectChain[1].StatusCode != nethttp.StatusFound {
		t.Errorf("RedirectChain[1].StatusCode = %d, want %d (mid's redirect)", svc.RedirectChain[1].StatusCode, nethttp.StatusFound)
	}
	if !strings.Contains(svc.RedirectChain[0].URL, strconv.Itoa(originPort)) {
		t.Errorf("RedirectChain[0].URL = %q, want to reference the origin port", svc.RedirectChain[0].URL)
	}
	if !strings.Contains(svc.RedirectChain[1].URL, strconv.Itoa(midPort)) {
		t.Errorf("RedirectChain[1].URL = %q, want to reference the mid port", svc.RedirectChain[1].URL)
	}
}

// TestProbe_RedirectLoop_BoundedByMaxRedirects proves a redirect loop
// (A -> B -> A -> B -> ...) terminates promptly and makes a bounded
// number of requests, rather than looping until some external timeout,
// consuming unbounded resources, or hanging.
func TestProbe_RedirectLoop_BoundedByMaxRedirects(t *testing.T) {
	var hitCount int32
	var portB int

	// Both hops use distinct hostnames (both allowed, both resolved via
	// the fake resolver to the same loopback IP) rather than raw IP
	// literals, so this genuinely exercises the redirect-following /
	// re-resolution path for each hop instead of being short-circuited
	// by a single scope check.
	var srvA, srvB *httptest.Server
	srvB = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hitCount, 1)
		nethttp.Redirect(w, r, srvA.URL, nethttp.StatusFound)
	}))
	defer srvB.Close()
	ipB, portB := testServerIPPort(t, srvB)

	srvA = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&hitCount, 1)
		nethttp.Redirect(w, r, "http://loopb.test:"+strconv.Itoa(portB)+"/", nethttp.StatusFound)
	}))
	defer srvA.Close()
	ipA, portA := testServerIPPort(t, srvA)
	srvA.URL = "http://loopa.test:" + strconv.Itoa(portA)

	const maxRedirects = 5
	v := &hostValidator{allowedHosts: map[string]bool{"loopa.test": true, "loopb.test": true}, allowedIPs: map[string]bool{ipA.String(): true}}
	resolver := dns.NewFakeResolver()
	resolver.Hosts["loopa.test"] = []net.IP{ipA}
	resolver.Hosts["loopb.test"] = []net.IP{ipB}
	p := NewProber(v, resolver, Config{Timeout: 5 * time.Second, MaxRedirects: maxRedirects}, nil)

	done := make(chan struct{})
	var probeErr error
	go func() {
		_, _, probeErr = p.Probe(context.Background(), ipA, portA, "loopa.test")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Probe hung in a redirect loop instead of terminating at MaxRedirects")
	}
	if probeErr != nil {
		t.Fatalf("Probe: %v", probeErr)
	}

	hits := atomic.LoadInt32(&hitCount)
	// http.Client follows up to MaxRedirects hops beyond the original
	// request, so the request count is bounded by roughly MaxRedirects+2
	// (original + each hop); it must not be allowed to grow unbounded.
	if hits > maxRedirects+3 {
		t.Errorf("redirect loop produced %d requests, want <= %d -- MaxRedirects is not bounding the loop", hits, maxRedirects+3)
	}
	t.Logf("redirect loop produced %d requests (bound: MaxRedirects=%d)", hits, maxRedirects)
}
