// Phase 3.4 SSRF callback infrastructure.
//
// SSRFCallbackServer is a minimal, local, in-lab HTTP server that
// RECORDS incoming requests keyed by a correlation token embedded in
// the request path -- nothing more. It implements
// internal/detectors/ssrf.CallbackClient directly, so the real
// ssrf.Detector can be pointed at it in tests exactly as it would be
// pointed at a real operator-configured callback service in production
// (see docs/phase-3-4-ssrf.md "Callback architecture").
//
// SECURITY: this server NEVER proxies, forwards, or fetches anything.
// Its handler makes zero outbound network calls anywhere in its
// implementation -- it only appends an in-memory record and returns a
// fixed acknowledgment body, regardless of what it's sent, regardless
// of headers, method, or body content. See
// TestSSRFCallbackServer_NeverProxiesRegardlessOfInput
// (callback_test.go) for the direct proof: a request carrying
// "forward-to"-shaped headers/body gets the identical response and
// produces zero additional network activity.
package lab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/detectors/ssrf"
)

// SSRFCallbackServer is lab's implementation of
// ssrf.CallbackClient: a real local HTTP server plus an in-memory,
// token-keyed observation log.
type SSRFCallbackServer struct {
	addr string // literal host:port once the listener is up

	mu  sync.Mutex
	obs map[string][]ssrf.Observation
}

// newSSRFCallbackServer builds the recorder and starts its HTTP
// listener on ip (a fixed lab-only loopback address), returning the
// recorder itself (for detector use) and the underlying *httptest.Server
// (for the caller to add to Lab.servers so Close() shuts it down).
func newSSRFCallbackServer(ip string) (*SSRFCallbackServer, *httptest.Server, error) {
	c := &SSRFCallbackServer{obs: map[string][]ssrf.Observation{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/cb/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/cb/")
		c.mu.Lock()
		c.obs[token] = append(c.obs[token], ssrf.Observation{
			Method:     r.Method,
			Path:       r.URL.Path,
			RemoteAddr: r.RemoteAddr,
			Timestamp:  time.Now().UTC(),
		})
		c.mu.Unlock()
		// Fixed acknowledgment, regardless of anything about the
		// request -- see the package doc comment above.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv, err := newServerOn(ip, mux)
	if err != nil {
		return nil, nil, err
	}
	c.addr = srv.Listener.Addr().String()
	return c, srv, nil
}

// NewToken implements ssrf.CallbackClient.
func (c *SSRFCallbackServer) NewToken(ctx context.Context) (token, callbackURL string, err error) {
	token = uuid.NewString()
	return token, "http://" + c.addr + "/cb/" + token, nil
}

// Observations implements ssrf.CallbackClient.
func (c *SSRFCallbackServer) Observations(ctx context.Context, token string) ([]ssrf.Observation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.obs[token]
	if len(src) == 0 {
		return nil, nil
	}
	out := make([]ssrf.Observation, len(src))
	copy(out, src)
	return out, nil
}

// InjectObservation is a TEST-ONLY helper that records a callback as if
// it had actually arrived over HTTP, without making a real request --
// used to test callback-arrives-during-polling and stale/duplicate
// scenarios deterministically, without depending on goroutine timing.
// Never called by any fixture or by the detector itself.
func (c *SSRFCallbackServer) InjectObservation(token string, o ssrf.Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.obs[token] = append(c.obs[token], o)
}

// Addr returns the callback server's literal host:port.
func (c *SSRFCallbackServer) Addr() string { return c.addr }
