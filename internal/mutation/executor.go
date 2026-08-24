package mutation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// ExecutorConfig bounds an Executor's behavior. Every limit here is a
// real, enforced ceiling, not documentation -- see
// docs/phase-3-17-request-mutation.md section 10.
type ExecutorConfig struct {
	Timeout               time.Duration
	MaxRedirects          int
	MaxRequestBodyBytes   int64
	MaxResponseBodyBytes  int64
	MaxConcurrentRequests int
	// MaxMutationsPerTarget/MaxTotalMutations bound how many MUTATED
	// (Origin == OriginMutated) requests this Executor will ever
	// execute -- 0 means unbounded. An ORIGINAL/baseline request is
	// never charged against either budget (see this field's discussion
	// in the architecture doc section 10).
	MaxMutationsPerTarget int
	MaxTotalMutations     int
	UserAgent             string
}

const defaultMaxResponseBodyBytes = 256 * 1024

func (c *ExecutorConfig) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxRedirects < 0 {
		c.MaxRedirects = 0
	}
	if c.MaxConcurrentRequests <= 0 {
		c.MaxConcurrentRequests = 5
	}
	if c.MaxResponseBodyBytes <= 0 {
		c.MaxResponseBodyBytes = defaultMaxResponseBodyBytes
	}
	if c.UserAgent == "" {
		c.UserAgent = "sakanner-mutation/1.0"
	}
}

// SessionContext carries the session/identity state Execute should
// attach to a request, as plain data -- never as an *auth.Session.
// This package never imports internal/auth (see
// docs/phase-3-17-request-mutation.md section 6): a caller that has a
// real *auth.Session builds a SessionContext from it via
// Session.JarFor/HeadersFor, exactly as internal/orchestration already
// does for internal/crawler.Options. The zero value is a fully valid,
// unauthenticated session.
type SessionContext struct {
	Jar             nethttp.CookieJar
	Headers         map[string]string
	PinnedHost      string
	IdentityContext string
}

// Executor is the sanctioned way to execute a canonical Request. It
// wraps safedial.Dialer exactly as internal/detection.Executor already
// does -- the same scope-safe dialing logic, the same "never trust a
// single check" defense in depth, applied to a Request instead of a
// Target-relative *http.Request.
type Executor struct {
	validator scope.Validator
	dialer    *safedial.Dialer
	cfg       ExecutorConfig
	sem       chan struct{}

	totalRequests  atomic.Int64
	totalMutations atomic.Int64

	mu        sync.Mutex
	perTarget map[string]int64
}

// NewExecutor builds an Executor. validator/resolver should be the
// same scope.Validator/dns.Resolver the rest of a scan job uses --
// never a private instance.
func NewExecutor(validator scope.Validator, resolver dns.Resolver, cfg ExecutorConfig) *Executor {
	cfg.applyDefaults()
	return &Executor{
		validator: validator,
		dialer:    safedial.New(validator, resolver),
		cfg:       cfg,
		sem:       make(chan struct{}, cfg.MaxConcurrentRequests),
		perTarget: make(map[string]int64),
	}
}

// RequestCount returns how many requests actually reached the network
// (i.e. passed every pre-flight/scope/budget check) so far.
func (x *Executor) RequestCount() int64 {
	return x.totalRequests.Load()
}

// Execute performs req, attaching sess's cookies/headers when req's
// host matches sess.PinnedHost (host-pinned, exactly like
// auth.Session.NewClient/internal/crawler already enforce), and always
// re-validating scope immediately before dialing -- see
// docs/phase-3-17-request-mutation.md section 7. It never returns a
// nil Response: even a rejected/failed request gets a populated
// Response with Outcome set, so a caller can inspect what happened
// without needing to parse err.
func (x *Executor) Execute(ctx context.Context, req Request, sess SessionContext) (Response, error) {
	start := time.Now()
	base := Response{RequestOrigin: req.Origin, MutationID: req.MutationID, IdentityContext: req.IdentityContext, ScanJobID: req.ScanJobID, HTTPServiceID: req.HTTPServiceID, EndpointID: req.EndpointID}

	if req.Host == "" {
		base.Outcome, base.Error = OutcomeInvalidRequest, "request has an empty host"
		return base, errors.New("mutation: request has an empty host")
	}
	if req.Method == "" {
		base.Outcome, base.Error = OutcomeInvalidRequest, "request has an empty method"
		return base, errors.New("mutation: request has an empty method")
	}
	if x.cfg.MaxRequestBodyBytes > 0 && int64(len(req.Body)) > x.cfg.MaxRequestBodyBytes {
		base.Outcome, base.Error = OutcomeInvalidRequest, fmt.Sprintf("request body of %d bytes exceeds the configured limit of %d", len(req.Body), x.cfg.MaxRequestBodyBytes)
		return base, fmt.Errorf("mutation: %s", base.Error)
	}

	if req.Origin == OriginMutated {
		if err := x.chargeMutationBudget(req); err != nil {
			base.Outcome, base.Error = OutcomeInvalidRequest, err.Error()
			return base, fmt.Errorf("mutation: %w", err)
		}
	}

	ip, err := x.resolveAndValidate(ctx, req)
	if err != nil {
		base.Outcome, base.Error = OutcomeScopeRejected, sanitizeErrorMessage(err)
		return base, err
	}

	select {
	case x.sem <- struct{}{}:
	case <-ctx.Done():
		base.Outcome, base.Error = OutcomeCancelled, ctx.Err().Error()
		return base, ctx.Err()
	}
	defer func() { <-x.sem }()

	x.totalRequests.Add(1)

	var chain []models.RedirectHop
	client := x.dialer.NewClient(req.Host, ip, nil, &chain, x.cfg.Timeout, x.cfg.MaxRedirects)
	if sess.Jar != nil && sess.PinnedHost != "" && strings.EqualFold(req.Host, sess.PinnedHost) {
		client.Jar = sess.Jar
	}
	if len(sess.Headers) > 0 {
		client.Transport = &safedial.PinnedRoundTripper{Base: client.Transport, Headers: sess.Headers, PinnedHost: sess.PinnedHost}
	}

	httpReq, err := buildHTTPRequest(ctx, req)
	if err != nil {
		base.Outcome, base.Error = OutcomeInvalidRequest, sanitizeErrorMessage(err)
		return base, fmt.Errorf("mutation: build http request: %w", err)
	}
	httpReq.Header.Set("User-Agent", x.cfg.UserAgent)

	httpResp, err := client.Do(httpReq)
	base.Duration = time.Since(start)
	base.RedirectChain = chain
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			base.Outcome = OutcomeCancelled
		case errors.Is(err, context.DeadlineExceeded):
			base.Outcome = OutcomeTimeout
		default:
			base.Outcome = OutcomeTransportError
		}
		base.Error = sanitizeErrorMessage(err)
		return base, err
	}
	defer httpResp.Body.Close()

	body, truncated, err := readBounded(httpResp.Body, x.cfg.MaxResponseBodyBytes)
	base.Duration = time.Since(start)
	if err != nil {
		base.Outcome, base.Error = OutcomeTransportError, sanitizeErrorMessage(err)
		return base, fmt.Errorf("mutation: read response body: %w", err)
	}

	base.Outcome = OutcomeSuccess
	base.StatusCode = httpResp.StatusCode
	base.Headers = httpResp.Header.Clone()
	base.ContentType = httpResp.Header.Get("Content-Type")
	base.Body = body
	base.BodySize = int64(len(body))
	base.Truncated = truncated
	return base, nil
}

// resolveAndValidate returns a scope-validated IP to dial for req --
// reusing req.IP (re-checked via CheckResolved, defense in depth,
// exactly like internal/detection.Executor.Do) when already known, or
// resolving it fresh via the exact function internal/auth already uses
// for the same "validate a host before ever dialing it" purpose when
// it is not.
func (x *Executor) resolveAndValidate(ctx context.Context, req Request) (net.IP, error) {
	if req.IP != nil {
		decision, err := x.validator.CheckResolved(ctx, req.Host, req.IP)
		if err != nil {
			return nil, fmt.Errorf("scope check for %s: %w", req.Host, err)
		}
		if !decision.Allowed {
			return nil, fmt.Errorf("%s (%s) is out of scope: %s", req.Host, req.IP, decision.Reason)
		}
		return req.IP, nil
	}
	ip, err := x.dialer.ResolveInScope(ctx, req.Host)
	if err != nil {
		return nil, fmt.Errorf("%s is not in scope or could not be resolved: %w", req.Host, err)
	}
	return ip, nil
}

func (x *Executor) chargeMutationBudget(req Request) error {
	if x.cfg.MaxTotalMutations > 0 {
		if x.totalMutations.Add(1) > int64(x.cfg.MaxTotalMutations) {
			return fmt.Errorf("total mutation budget of %d exhausted", x.cfg.MaxTotalMutations)
		}
	} else {
		x.totalMutations.Add(1)
	}
	if x.cfg.MaxMutationsPerTarget > 0 {
		key := targetKey(req)
		x.mu.Lock()
		x.perTarget[key]++
		n := x.perTarget[key]
		x.mu.Unlock()
		if n > int64(x.cfg.MaxMutationsPerTarget) {
			return fmt.Errorf("per-target mutation budget of %d exhausted for endpoint %q parameter %q", x.cfg.MaxMutationsPerTarget, req.EndpointID, req.Parameter)
		}
	}
	return nil
}

func targetKey(req Request) string {
	return req.EndpointID + "\x00" + req.Parameter + "\x00" + req.ParameterLocation
}

func buildHTTPRequest(ctx context.Context, req Request) (*nethttp.Request, error) {
	u := req.URL()
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}
	httpReq, err := nethttp.NewRequestWithContext(ctx, req.Method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	// Sorted key order -- deterministic wire header order for two
	// Requests carrying the identical logical header set (see
	// docs/phase-3-17-request-mutation.md section 12).
	keys := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Headers[k] {
			httpReq.Header.Add(k, v)
		}
	}
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}
	for _, c := range req.Cookies {
		httpReq.AddCookie(c)
	}
	return httpReq, nil
}

// readBounded reads up to limit bytes from r, reporting whether more
// data existed than was kept -- the same "read limit+1, check length"
// idiom internal/http.Prober already uses.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// sanitizeErrorMessage returns err's message with embedded newline
// control characters neutralized -- an error string can otherwise
// carry attacker-influenced bytes (a mutated header/URL value) straight
// into a log line. This is a plain text-safety pass, not secret
// redaction (Execute never has a credential to redact in the first
// place -- see docs/phase-3-17-request-mutation.md section 9).
func sanitizeErrorMessage(err error) string {
	s := err.Error()
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
