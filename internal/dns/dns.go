// Package dns wraps DNS resolution behind an interface so pipeline
// stages that need name resolution (subdomain enumeration, HTTP probing)
// can depend on Resolver rather than net directly, keeping them testable
// against fakes.
package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Resolver performs context-aware, timeout-bounded DNS lookups.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// resolver wraps net.Resolver, applying a per-call timeout on top of
// whatever deadline ctx already carries.
type resolver struct {
	inner   *net.Resolver
	timeout time.Duration
}

// New returns a Resolver backed by Go's net.Resolver. timeout bounds each
// individual lookup; ctx cancellation is still honored independently.
func New(timeout time.Duration) Resolver {
	return &resolver{inner: &net.Resolver{}, timeout: timeout}
}

func (r *resolver) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *resolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()

	addrs, err := r.inner.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup host %q: %w", host, err)
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

func (r *resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()

	cname, err := r.inner.LookupCNAME(ctx, host)
	if err != nil {
		return "", fmt.Errorf("dns: lookup cname %q: %w", host, err)
	}
	return cname, nil
}

func (r *resolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()

	mx, err := r.inner.LookupMX(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup mx %q: %w", host, err)
	}
	return mx, nil
}

func (r *resolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()

	txt, err := r.inner.LookupTXT(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup txt %q: %w", host, err)
	}
	return txt, nil
}

func (r *resolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	ctx, cancel := r.withTimeout(ctx)
	defer cancel()

	ns, err := r.inner.LookupNS(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup ns %q: %w", host, err)
	}
	return ns, nil
}
