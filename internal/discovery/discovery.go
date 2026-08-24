// Package discovery implements subdomain enumeration. Enumerator is the
// pluggable interface; NewWordlistEnumerator is the Phase 1 built-in
// implementation, leaving room to plug in an external tool (e.g.
// subfinder, amass) later via pkg/plugins without changing callers.
package discovery

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"sakanner/internal/dns"
	"sakanner/pkg/plugins"
)

// Candidate is one enumerated name, along with the source that produced
// it and, if resolvable, the IPs it resolved to.
type Candidate struct {
	Name   string
	Source string
	IPs    []string
}

// Enumerator discovers candidate subdomains of domain.
type Enumerator interface {
	Name() string
	// Enumerate sends a Candidate on out for every wordlist entry that
	// resolves, returning when done or ctx is cancelled. It does not
	// close out, since a caller may fan multiple Enumerators into one
	// shared channel.
	Enumerate(ctx context.Context, domain string, out chan<- Candidate) error
}

type wordlistEnumerator struct {
	wordlist    []string
	resolver    dns.Resolver
	concurrency int
}

// NewWordlistEnumerator returns an Enumerator that tries "word.domain"
// for each entry in wordlist and reports the ones that resolve.
func NewWordlistEnumerator(wordlist []string, resolver dns.Resolver, concurrency int) Enumerator {
	if concurrency <= 0 {
		concurrency = 1
	}
	return &wordlistEnumerator{wordlist: wordlist, resolver: resolver, concurrency: concurrency}
}

func (e *wordlistEnumerator) Name() string { return "wordlist" }

func (e *wordlistEnumerator) Enumerate(ctx context.Context, domain string, out chan<- Candidate) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(e.concurrency)

	for _, word := range e.wordlist {
		word := word
		g.Go(func() error {
			candidate := fmt.Sprintf("%s.%s", word, domain)
			ips, err := e.resolver.LookupHost(gctx, candidate)
			if err != nil {
				if gctx.Err() != nil {
					return gctx.Err() // cancelled/deadline exceeded -- propagate, don't mask as "doesn't resolve"
				}
				return nil // ordinary resolution failure (e.g. NXDOMAIN); not a scan error
			}

			ipStrs := make([]string, len(ips))
			for i, ip := range ips {
				ipStrs[i] = ip.String()
			}

			select {
			case out <- Candidate{Name: candidate, Source: e.Name(), IPs: ipStrs}:
			case <-gctx.Done():
			}
			return nil
		})
	}

	err := g.Wait()
	return err
}

// NewEnumerator selects an Enumerator per sakanner's uniform
// auto|native|<tool> backend contract (see pkg/plugins.Resolve):
// subfinder if backend selects it, the built-in wordlist enumerator
// otherwise. subfinder only enumerates names -- every name it reports
// still goes through resolver here before being reported as a Candidate,
// exactly like the wordlist path, so scope validation downstream is
// unaffected by which backend produced the name.
func NewEnumerator(backend string, wordlist []string, resolver dns.Resolver, concurrency int, logger *slog.Logger) (Enumerator, error) {
	decision, err := plugins.Resolve(backend, plugins.Subfinder, false, logger)
	if err != nil {
		return nil, err
	}
	if decision == plugins.UseTool {
		path, _ := plugins.Detect(plugins.Subfinder.BinaryName)
		return NewSubfinderEnumerator(path, resolver, concurrency), nil
	}
	return NewWordlistEnumerator(wordlist, resolver, concurrency), nil
}

type subfinderEnumerator struct {
	binary      string
	resolver    dns.Resolver
	concurrency int
}

// NewSubfinderEnumerator returns an Enumerator backed by the subfinder
// CLI tool (found at binary). Every name subfinder reports is resolved
// and reported as a Candidate only if it resolves, same as
// NewWordlistEnumerator -- subfinder itself never dials anything.
func NewSubfinderEnumerator(binary string, resolver dns.Resolver, concurrency int) Enumerator {
	if concurrency <= 0 {
		concurrency = 1
	}
	return &subfinderEnumerator{binary: binary, resolver: resolver, concurrency: concurrency}
}

func (e *subfinderEnumerator) Name() string { return "subfinder" }

type subfinderLine struct {
	Host string `json:"host"`
}

func (e *subfinderEnumerator) Enumerate(ctx context.Context, domain string, out chan<- Candidate) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(e.concurrency)

	names := make(chan string, 64)
	runErrCh := make(chan error, 1)

	// gctx (not the outer ctx) bounds both this producer and every
	// resolve below -- so a resolve failure that fails the whole group
	// promptly stops the subprocess too, instead of leaving it running
	// until the outer ctx (which the group doesn't own) is cancelled.
	go func() {
		defer close(names)
		runErrCh <- plugins.RunJSONLines(gctx, e.binary, []string{"-d", domain, "-silent", "-json"}, func(line subfinderLine) error {
			if line.Host == "" {
				return nil
			}
			select {
			case names <- line.Host:
			case <-gctx.Done():
				return gctx.Err()
			}
			return nil
		})
	}()

	for name := range names {
		name := name
		g.Go(func() error {
			ips, err := e.resolver.LookupHost(gctx, name)
			if err != nil {
				if gctx.Err() != nil {
					return gctx.Err()
				}
				return nil // ordinary resolution failure; not a scan error
			}
			ipStrs := make([]string, len(ips))
			for i, ip := range ips {
				ipStrs[i] = ip.String()
			}
			select {
			case out <- Candidate{Name: name, Source: e.Name(), IPs: ipStrs}:
			case <-gctx.Done():
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}
	return <-runErrCh
}
