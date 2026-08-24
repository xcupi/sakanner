// Package ports implements port/service discovery. Scanner is the
// pluggable interface; NewTCPConnectScanner is the Phase 1 built-in
// implementation, leaving room to plug in an external tool (e.g. nmap)
// later via pkg/plugins without changing callers.
package ports

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"sakanner/internal/scope"
)

// Result is one port's scan outcome.
type Result struct {
	Port  int
	Open  bool
	Error error
}

// Scanner discovers open TCP ports on an IP address.
type Scanner interface {
	Name() string
	// Scan checks each of ports against ip (the address actually
	// dialed) and streams a Result per port on the returned channel,
	// which is closed when scanning completes or ctx is cancelled. Every
	// dial is validated against scope immediately beforehand via
	// CheckResolved(hostname, ip) -- hostname is required so
	// domain-based scope rules (the common case) authorize the dial;
	// pass the literal IP's string form when there is no separate
	// hostname (e.g. an IP/CIDR target).
	Scan(ctx context.Context, hostname string, ip net.IP, ports []int) (<-chan Result, error)
}

type tcpConnectScanner struct {
	validator   scope.Validator
	dialTimeout time.Duration
	// sem bounds the total number of in-flight dials across every Scan
	// call made through this scanner instance -- not per call. A Scanner
	// is constructed once per scan job and reused across every host
	// orchestration scans, so this is what makes "concurrency" mean the
	// true aggregate dial concurrency for the whole job, rather than
	// silently compounding into (concurrency * concurrent hosts) if each
	// Scan call bounded itself independently.
	sem     *semaphore.Weighted
	limiter *rate.Limiter
}

// NewTCPConnectScanner returns a Scanner that opens (and immediately
// closes) a TCP connection to each candidate port. validator is required:
// every dial is checked against it immediately beforehand, so a
// deny-everything validator results in zero dial attempts.
func NewTCPConnectScanner(validator scope.Validator, dialTimeout time.Duration, concurrency int, limiter *rate.Limiter) Scanner {
	if concurrency <= 0 {
		concurrency = 1
	}
	return &tcpConnectScanner{validator: validator, dialTimeout: dialTimeout, sem: semaphore.NewWeighted(int64(concurrency)), limiter: limiter}
}

func (s *tcpConnectScanner) Name() string { return "tcp-connect" }

func (s *tcpConnectScanner) Scan(ctx context.Context, hostname string, ip net.IP, portList []int) (<-chan Result, error) {
	if ip == nil {
		return nil, fmt.Errorf("ports: nil IP")
	}

	decision, err := s.validator.CheckResolved(ctx, hostname, ip)
	if err != nil {
		return nil, fmt.Errorf("ports: scope check for %s: %w", ip, err)
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("ports: %s is out of scope: %s", ip, decision.Reason)
	}

	out := make(chan Result)

	go func() {
		defer close(out)

		g, gctx := errgroup.WithContext(ctx)

		for _, port := range portList {
			port := port
			g.Go(func() error {
				// Acquire a shared slot before doing any work for this
				// port -- this, not errgroup's own limit, is what bounds
				// true aggregate concurrency across every host being
				// scanned concurrently by the caller.
				if err := s.sem.Acquire(gctx, 1); err != nil {
					return nil //nolint:nilerr // ctx cancellation ends the scan, not an error to surface per-port
				}
				defer s.sem.Release(1)

				if s.limiter != nil {
					if err := s.limiter.Wait(gctx); err != nil {
						return nil //nolint:nilerr // ctx cancellation ends the scan, not an error to surface per-port
					}
				}

				// Re-validate immediately before every dial, not just
				// once at the top of Scan -- the single point where a
				// socket is actually opened is the only place this
				// guarantee matters.
				d, err := s.validator.CheckResolved(gctx, hostname, ip)
				if err != nil || !d.Allowed {
					select {
					case out <- Result{Port: port, Open: false, Error: fmt.Errorf("ports: scope check denied dial to %s:%d", ip, port)}:
					case <-gctx.Done():
					}
					return nil
				}

				open, dialErr := dialOnce(gctx, ip, port, s.dialTimeout)
				select {
				case out <- Result{Port: port, Open: open, Error: dialErr}:
				case <-gctx.Done():
				}
				return nil
			})
		}
		_ = g.Wait()
	}()

	return out, nil
}

func dialOnce(ctx context.Context, ip net.IP, port int, timeout time.Duration) (open bool, err error) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, nil // connection refused/timeout just means closed; not a scan error
	}
	conn.Close()
	return true, nil
}
