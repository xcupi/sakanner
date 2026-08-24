// Package safedial is sakanner's shared scope-safe HTTP dialing logic,
// factored out of internal/http so any stage that needs to make its own
// HTTP requests against a scanned target (the prober, and now the
// crawler) shares one implementation of the highest-risk code path in
// the whole platform, rather than each stage re-deriving it independently.
//
// Dialer.NewClient builds an *http.Client that dials the exact,
// scope-validated IP already resolved for the original host, and never
// lets net/http's transport re-resolve a hostname on its own -- that
// would open a DNS-rebinding TOCTOU gap between the scope check and the
// connection. A redirect to a different host is resolved and
// re-validated by the dialer itself, IP by IP, before any dial is
// attempted; the client's CheckRedirect additionally re-checks scope on
// every hop and stops the chain (not the whole request) the moment a
// hop is out of scope.
package safedial

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	nethttp "net/http"
	"strings"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// TLSCapture receives the leaf certificate's details from a successful
// TLS handshake, if any. Verification is intentionally skipped (see
// NewClient) so this is populated for self-signed/expired/mismatched
// certificates too -- capturing them as evidence, not trusting them.
type TLSCapture struct {
	Subject  string
	Issuer   string
	NotAfter time.Time
	Version  string   // e.g. "TLS 1.3"
	SANs     []string // subject alternative names: DNS names + IP addresses
	// SelfSigned is a heuristic (Subject == Issuer on the leaf
	// certificate), not cryptographic proof -- verification is skipped
	// entirely (see NewClient), so this is informational evidence, not a
	// trust decision.
	SelfSigned bool
}

// Dialer holds the dependencies every scope-safe HTTP client built by
// this package needs.
type Dialer struct {
	Validator scope.Validator
	Resolver  dns.Resolver
}

// New returns a Dialer.
func New(validator scope.Validator, resolver dns.Resolver) *Dialer {
	return &Dialer{Validator: validator, Resolver: resolver}
}

// NewClient builds an *http.Client whose Transport dials only the exact
// scope-validated originalIP for originalHost, and for any other host
// (i.e. a redirect target) resolves and validates it itself -- IP by IP,
// via d.Resolver -- before dialing, rather than letting the transport
// resolve on its own. capture is filled in on a successful TLS
// handshake; chain (if non-nil) accumulates one RedirectHop per
// intermediate hop actually followed (the final response is not
// included -- callers already have its URL/status directly). timeout
// bounds the whole client; maxRedirects bounds how many hops
// CheckRedirect will follow before truncating the chain.
func (d *Dialer) NewClient(originalHost string, originalIP net.IP, capture *TLSCapture, chain *[]models.RedirectHop, timeout time.Duration, maxRedirects int) *nethttp.Client {
	if maxRedirects < 0 {
		maxRedirects = 0
	}

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.dialValidated(ctx, network, addr, originalHost, originalIP)
	}

	transport := &nethttp.Transport{
		// A fresh Transport is built for every single request through
		// this client (the client itself is typically used for exactly
		// one request/probe), so keep-alive pooling has no reuse benefit
		// here -- it would only leave an idle connection, and the
		// goroutine reading it, alive indefinitely (a zero-value
		// Transport's IdleConnTimeout is unbounded), which accumulates
		// across every request a long-running process performs.
		DisableKeepAlives: true,
		DialContext:       dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("safedial: split host port %q: %w", addr, err)
			}
			rawConn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// InsecureSkipVerify is intentional: a security scanner must be
			// able to probe targets with self-signed, expired, or
			// hostname-mismatched certificates (common on real targets)
			// rather than refusing to connect. The certificate is still
			// captured as evidence below.
			tlsConn := tls.Client(rawConn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) //nolint:gosec
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("safedial: tls handshake to %s: %w", addr, err)
			}
			if capture != nil {
				state := tlsConn.ConnectionState()
				capture.Version = tls.VersionName(state.Version)
				if len(state.PeerCertificates) > 0 {
					cert := state.PeerCertificates[0]
					capture.Subject = cert.Subject.String()
					capture.Issuer = cert.Issuer.String()
					capture.NotAfter = cert.NotAfter
					capture.SelfSigned = cert.Subject.String() == cert.Issuer.String()
					sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
					sans = append(sans, cert.DNSNames...)
					for _, ip := range cert.IPAddresses {
						sans = append(sans, ip.String())
					}
					capture.SANs = sans
				}
			}
			return tlsConn, nil
		},
	}

	return &nethttp.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
			// req.Response is the redirect response that caused this
			// request to be created (net/http sets it specifically for
			// CheckRedirect's use) -- recording it here, hop by hop, is
			// how the full chain is captured without re-deriving it from
			// via (whose elements don't reliably carry their own
			// Response).
			if chain != nil && req.Response != nil {
				*chain = append(*chain, models.RedirectHop{URL: req.Response.Request.URL.String(), StatusCode: req.Response.StatusCode})
			}
			if len(via) > maxRedirects {
				return nethttp.ErrUseLastResponse
			}
			// ErrUseLastResponse stops following the chain and returns the
			// last response with a nil error, exactly like the
			// max-redirects case above -- an out-of-scope hop degrades the
			// result (chain truncated) rather than failing the request
			// outright. A generic error here would instead fail
			// client.Do for the whole request, which is not what we want.
			decision, err := d.Validator.CheckHost(req.Context(), req.URL.Hostname())
			if err != nil || !decision.Allowed {
				return nethttp.ErrUseLastResponse
			}
			return nil
		},
	}
}

// dialValidated resolves addr's host to a scope-validated IP -- reusing
// originalIP without re-resolving when the host matches the host the
// client was built for, and independently resolving+validating via
// d.Resolver otherwise (the redirect-to-a-different-host case) -- then
// dials that literal IP. The transport never gets a chance to resolve
// addr's hostname itself.
func (d *Dialer) dialValidated(ctx context.Context, network, addr, originalHost string, originalIP net.IP) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safedial: split host port %q: %w", addr, err)
	}

	targetIP := originalIP
	if !strings.EqualFold(host, originalHost) {
		targetIP, err = d.resolveInScope(ctx, host)
		if err != nil {
			return nil, err
		}
	} else {
		// Defense in depth: re-validate even the pre-resolved original IP
		// immediately before dialing, not just once upstream. Uses
		// CheckResolved (not CheckIP) so a domain-based scope rule -- the
		// common case -- actually authorizes this dial; CheckIP alone
		// only understands IP/CIDR-type rules.
		decision, err := d.Validator.CheckResolved(ctx, originalHost, originalIP)
		if err != nil {
			return nil, fmt.Errorf("safedial: scope check for %s: %w", originalIP, err)
		}
		if !decision.Allowed {
			return nil, fmt.Errorf("safedial: %s is out of scope: %s", originalIP, decision.Reason)
		}
	}

	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(targetIP.String(), port))
}

// ResolveInScope resolves host and returns the first IP that passes
// scope validation -- exported so a caller that needs to scope-validate
// a host BEFORE ever building a Dialer-backed client (e.g.
// internal/auth, resolving a login URL's host prior to dialing it) can
// reuse this exact check rather than re-deriving it. Identical to the
// validation dialValidated itself performs for a redirect to a
// different host -- one implementation, two call sites.
func (d *Dialer) ResolveInScope(ctx context.Context, host string) (net.IP, error) {
	return d.resolveInScope(ctx, host)
}

// PinnedRoundTripper attaches a fixed set of headers to every request
// whose URL host matches PinnedHost, and STRIPS them from every other
// request -- checked per actual outgoing request (including every
// redirect hop this RoundTripper is invoked for), never merely once
// when a client is constructed.
//
// Verified empirically during Phase 3.15's development (see
// docs/phase-3-15-authenticated-crawling.md "Why a shared pinned
// transport" for both the method and the corrected finding):
// net/http's OWN client already refuses to carry a manually-set
// Cookie/Authorization header across a redirect to a genuinely
// different HOST (a different hostname, not merely a different port on
// the same host -- an earlier version of this investigation's own test
// wrongly used two httptest servers that both defaulted to 127.0.0.1,
// which is NOT a cross-host scenario and produced a misleading result
// before being corrected). So this type is not closing a proven leak in
// net/http itself; it exists for two other reasons that are real:
//
//  1. The explicit STRIP-on-mismatch branch is required for correctness
//     of THIS type's own per-hop guarantee: net/http's Client.do()
//     copies headers from the ORIGINAL request onto every subsequent
//     hop's request object before that object ever reaches a
//     RoundTripper -- so a RoundTripper that only ADDS on a host match
//     and passes everything else through untouched would silently
//     forward a header it added on an earlier hop to a later,
//     different-host hop within the SAME RoundTripper chain. Add-only
//     was tried and failed a same-package test
//     (TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect, once its own
//     cross-host setup was fixed) before the strip branch was added.
//  2. Defense in depth: this is the one place in the codebase that
//     enforces a session's host-pinning security model (see
//     internal/auth.Session's CookiesFor/HeadersFor doc comments) at
//     the transport layer, independent of whatever net/http's own
//     redirect behavior happens to do in the Go version this code
//     eventually runs under.
//
// Both internal/auth.Session.NewClient and internal/crawler's own
// authenticated-crawl client construction use this ONE implementation
// -- a security-critical mechanism belongs in exactly one place, not
// two independently-maintained copies.
type PinnedRoundTripper struct {
	Base       nethttp.RoundTripper
	Headers    map[string]string
	PinnedHost string
}

func (t *PinnedRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	base := t.Base
	if base == nil {
		base = nethttp.DefaultTransport
	}
	if len(t.Headers) == 0 {
		return base.RoundTrip(req)
	}
	// Clone before mutating: req is owned by the caller (net/http's
	// RoundTripper contract forbids mutating the original request).
	cloned := req.Clone(req.Context())
	if strings.EqualFold(req.URL.Hostname(), t.PinnedHost) {
		for k, v := range t.Headers {
			cloned.Header.Set(k, v)
		}
	} else {
		// This is the critical branch, not a defensive no-op: net/http's
		// OWN Client.do() copies headers from a request onto the NEXT
		// hop's request object BEFORE that request ever reaches this
		// RoundTrip -- including a header this RoundTripper itself set on
		// an earlier, same-client hop to the pinned host. If this
		// RoundTripper only ADDED headers on a host match and passed
		// everything else through untouched, a header it set on hop 1
		// would already be sitting on hop 2's request by the time this
		// method is even called for hop 2, and returning early here would
		// silently forward it to a different host. Deleting on every
		// non-matching hop is what actually enforces the pin -- proven
		// necessary by TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect,
		// which failed against an earlier version of this method that
		// only added and never stripped.
		for k := range t.Headers {
			cloned.Header.Del(k)
		}
	}
	return base.RoundTrip(cloned)
}

// resolveInScope resolves host and returns the first IP that passes
// scope validation (via CheckResolved, so domain-based rules authorize
// it), erroring if none does.
func (d *Dialer) resolveInScope(ctx context.Context, host string) (net.IP, error) {
	ips, err := d.Resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safedial: resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		decision, err := d.Validator.CheckResolved(ctx, host, ip)
		if err == nil && decision.Allowed {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("safedial: no in-scope IP found for %q", host)
}
