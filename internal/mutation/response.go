package mutation

import (
	"net/http"
	"time"

	"sakanner/pkg/models"
)

// Outcome classifies what Execute produced, distinguishing a real HTTP
// response (any status code, including non-2xx -- that is still a
// successful execution) from every way a request can fail to produce
// one at all. See docs/phase-3-17-request-mutation.md section 5.
type Outcome string

const (
	// OutcomeSuccess means an HTTP response was received. StatusCode
	// may be anything, including 4xx/5xx -- a non-2xx response is not
	// itself a failure of execution.
	OutcomeSuccess Outcome = "SUCCESS"
	// OutcomeInvalidRequest means the request was rejected before any
	// network activity: malformed (empty host/method), an oversized
	// body, or a mutation/total budget already exhausted.
	OutcomeInvalidRequest Outcome = "INVALID_REQUEST"
	// OutcomeScopeRejected means scope.Validator denied the request's
	// host/IP, before any dial was attempted.
	OutcomeScopeRejected Outcome = "SCOPE_REJECTED"
	// OutcomeTimeout means the request was aborted because it exceeded
	// ExecutorConfig.Timeout.
	OutcomeTimeout Outcome = "TIMEOUT"
	// OutcomeCancelled means the caller's own context was cancelled
	// while the request was in flight (or while waiting for a
	// concurrency slot).
	OutcomeCancelled Outcome = "CANCELLED"
	// OutcomeTransportError covers every other network-level failure:
	// DNS resolution failure, connection refused, TLS handshake
	// failure, a connection reset mid-response, and so on.
	OutcomeTransportError Outcome = "TRANSPORT_ERROR"
)

// Response is the bounded result of one Execute call. Body is bounded
// by ExecutorConfig.MaxResponseBodyBytes; Truncated reports whether
// more data existed than was kept.
type Response struct {
	Outcome     Outcome
	StatusCode  int
	Headers     http.Header
	ContentType string
	Body        []byte
	BodySize    int64
	Truncated   bool

	RedirectChain []models.RedirectHop
	Duration      time.Duration
	// Error is a human-readable, secret-free description of why
	// Outcome is not OutcomeSuccess. Empty when Outcome ==
	// OutcomeSuccess.
	Error string

	// Provenance, carried through from the Request that produced this
	// Response -- so a caller holding only a Response (e.g. after
	// fanning results back through a channel) can still tell which
	// request produced it without needing to keep the Request around
	// too.
	RequestOrigin   Origin
	MutationID      string
	IdentityContext string
	ScanJobID       string
	HTTPServiceID   string
	EndpointID      string
}
