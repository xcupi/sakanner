package detection

import (
	"context"
	"fmt"
	nethttp "net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"sakanner/internal/dns"
	"sakanner/internal/mutation"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
)

// ExecutorConfig bounds an Executor's behavior. See
// internal/config.DetectionConfig, which this is built from in
// production.
type ExecutorConfig struct {
	// Concurrency bounds how many requests may be in flight across the
	// WHOLE Executor at once, regardless of how many detectors or
	// targets are running concurrently.
	Concurrency  int
	Limiter      *rate.Limiter
	Timeout      time.Duration
	MaxRedirects int
	UserAgent    string
	// MaxRequests is a hard ceiling on the total number of requests this
	// Executor will ever perform across its whole lifetime (i.e. one
	// Engine.Run). Do returns an error once reached, regardless of
	// scope/rate-limit state -- a backstop against a future detector bug
	// turning one scan into unbounded traffic against a target. 0 means
	// unbounded.
	MaxRequests int

	// MaxMutationsPerParameter/MaxActiveRequestsPerScan bound
	// ExecuteMutation specifically (Phase 3.19) -- mapped directly onto
	// internal/mutation.ExecutorConfig's own already-built-and-tested
	// MaxMutationsPerTarget/MaxTotalMutations budget (Phase 3.17), not
	// a new mechanism. 0 means unbounded, matching MaxRequests' own
	// convention. Requests issued via the pre-existing Do method are
	// NEVER charged against either of these -- they are bounded by
	// MaxRequests/Concurrency/Limiter exactly as before Phase 3.19.
	MaxMutationsPerParameter int
	MaxActiveRequestsPerScan int
}

// Executor is the ONLY sanctioned way a Detector may make an outbound
// HTTP request against a target. It wraps safedial.Dialer -- the same
// scope-safe dialing logic internal/http and internal/crawler already
// use for Phase 2's own probing/crawling -- so every detector-issued
// request gets identical scope validation (checked again here,
// immediately before dialing, even though the Target the engine handed
// the detector was itself already derived from scope-validated recon
// data: the same "never trust a single check" discipline safedial
// itself applies at every dial), redirect re-validation hop by hop, and
// TLS capture, without any individual detector re-deriving that logic
// itself -- see docs/phase-3-1-detection-engine.md "Request execution"
// and "Scope enforcement" for why a detector must never build its own
// http.Client or call net/http directly.
//
// Phase 3.19 adds ExecuteMutation, a second, additive method for a
// detector built on internal/mutation's canonical Request/Mutate model
// -- see docs/phase-3-19-active-detection.md section 2. Do's own
// implementation is otherwise UNCHANGED from Phase 3.1-3.18, except
// for one small, additive fix: it now also attaches this scan's own
// session (if any), so an existing detector incidentally gains
// authenticated execution the moment a scan itself authenticates,
// without ever touching a credential itself.
type Executor struct {
	dialer    *safedial.Dialer
	validator scope.Validator
	limiter   *rate.Limiter
	sem       chan struct{}
	cfg       ExecutorConfig
	session   mutation.SessionContext

	mutationExecutor *mutation.Executor

	requestCount atomic.Int64
}

// NewExecutor builds an Executor with no session attached -- every
// pre-Phase-3.19 caller (dozens of test files, every production
// callsite before this phase) is unaffected: a zero-value
// mutation.SessionContext{} attaches nothing to any request, exactly
// matching this function's own prior behavior byte for byte.
func NewExecutor(validator scope.Validator, resolver dns.Resolver, cfg ExecutorConfig) *Executor {
	return NewExecutorWithSession(validator, resolver, cfg, mutation.SessionContext{})
}

// NewExecutorWithSession is NewExecutor plus an explicit session to
// attach (host-pinned, exactly like every other session-aware
// component in this codebase) -- Phase 3.19's own addition, used by
// internal/orchestrator.buildDetectionExecutor when a scan
// authenticated. validator/resolver are the SAME scope.Validator/
// dns.Resolver the rest of the pipeline uses for this scan job --
// never a detector-private instance.
func NewExecutorWithSession(validator scope.Validator, resolver dns.Resolver, cfg ExecutorConfig, sess mutation.SessionContext) *Executor {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "sakanner-detection/1.0"
	}
	mutationExecutor := mutation.NewExecutor(validator, resolver, mutation.ExecutorConfig{
		Timeout: cfg.Timeout, MaxRedirects: cfg.MaxRedirects, UserAgent: cfg.UserAgent,
		MaxConcurrentRequests: cfg.Concurrency,
		MaxMutationsPerTarget: cfg.MaxMutationsPerParameter,
		MaxTotalMutations:     cfg.MaxActiveRequestsPerScan,
	})
	return &Executor{
		dialer:           safedial.New(validator, resolver),
		validator:        validator,
		limiter:          cfg.Limiter,
		sem:              make(chan struct{}, cfg.Concurrency),
		cfg:              cfg,
		session:          sess,
		mutationExecutor: mutationExecutor,
	}
}

// Do performs req against t: re-validates t's host/IP against scope,
// waits for the rate limiter and a free concurrency slot (both
// ctx-aware, so a cancelled ctx unblocks immediately rather than
// waiting), enforces the total-request ceiling, sets the configured
// User-Agent, and issues the request through a safedial-built client
// bound to t's exact IP -- redirects are followed and re-validated by
// that client exactly as they are for Phase 2's own HTTP probing.
//
// req should be built with a relative or t-relative URL (see
// docs/phase-3-1-detection-engine.md for the expected pattern); Do does
// not itself rewrite req.URL to match t -- callers construct req against
// t.URL/t.Path directly, then Do's scope check guards the dial.
func (x *Executor) Do(ctx context.Context, t Target, req *nethttp.Request) (*nethttp.Response, error) {
	if t.IP == nil {
		return nil, fmt.Errorf("detection: target %s has no resolved IP", t.Host)
	}

	// Defense in depth: this is the SAME check safedial.Dialer performs
	// again internally before every dial (including this one) -- see
	// safedial's own doc comment for why a single check is never
	// trusted alone. Performing it here too means an out-of-scope
	// target is rejected before Do even builds a client, not just
	// silently degraded once dialValidated notices later.
	decision, err := x.validator.CheckResolved(ctx, t.Host, t.IP)
	if err != nil {
		return nil, fmt.Errorf("detection: scope check for %s: %w", t.Host, err)
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("detection: target %s (%s) is out of scope: %s", t.Host, t.IP, decision.Reason)
	}

	if x.cfg.MaxRequests > 0 {
		if x.requestCount.Add(1) > int64(x.cfg.MaxRequests) {
			return nil, fmt.Errorf("detection: request budget of %d exhausted for this run", x.cfg.MaxRequests)
		}
	} else {
		x.requestCount.Add(1)
	}

	if x.limiter != nil {
		if err := x.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

	select {
	case x.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-x.sem }()

	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", x.cfg.UserAgent)

	client := x.dialer.NewClient(t.Host, t.IP, nil, nil, x.cfg.Timeout, x.cfg.MaxRedirects)
	// Phase 3.19: attach this scan's own session, host-pinned exactly
	// like every other session-aware client in this codebase
	// (auth.Session.NewClient, internal/crawler, internal/mutation.Executor)
	// -- a zero-value session (the pre-Phase-3.19 default) changes
	// nothing here; Do's behavior for an unauthenticated scan is
	// byte-for-byte identical to before this phase.
	if x.session.Jar != nil && x.session.PinnedHost != "" && strings.EqualFold(t.Host, x.session.PinnedHost) {
		client.Jar = x.session.Jar
	}
	if len(x.session.Headers) > 0 {
		client.Transport = &safedial.PinnedRoundTripper{Base: client.Transport, Headers: x.session.Headers, PinnedHost: x.session.PinnedHost}
	}
	return client.Do(req)
}

// ExecuteMutation runs req (built via mutation.NewRequestFromTarget and
// optionally mutation.Mutate) through internal/mutation.Executor --
// the exact same scope-safe, session-aware, resource-bounded execution
// path Phase 3.17 already built and tested, reused here rather than
// re-implemented (docs/phase-3-19-active-detection.md section 2). This
// is the ONLY execution path a Phase 3.19-style active detector uses;
// there is no detector-specific alternative anywhere in this package.
func (x *Executor) ExecuteMutation(ctx context.Context, req mutation.Request) (mutation.Response, error) {
	return x.mutationExecutor.Execute(ctx, req, x.session)
}

// RequestCount returns how many requests this Executor has issued so
// far across BOTH Do and ExecuteMutation (whether they succeeded or
// failed) -- for tests and Engine's own run summary. Phase 3.19 sums
// the two independently-tracked counters (Do-issued and
// ExecuteMutation-issued requests have different budget semantics --
// see ExecutorConfig's own doc comment -- but share one externally
// visible total, so DetectorSummary.RequestsIssued remains accurate
// regardless of which detectors ran).
func (x *Executor) RequestCount() int64 {
	return x.requestCount.Load() + x.mutationExecutor.RequestCount()
}
