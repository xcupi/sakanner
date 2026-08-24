package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"sakanner/internal/dns"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// dumpStruct renders v as text for a blanket "no secret substring
// anywhere in this" scan -- used by security_test.go so a future field
// added to a redacted summary type is covered automatically, not only
// by whatever specific fields today's test happens to assert on.
func dumpStruct(v any) string {
	return fmt.Sprintf("%+v", v)
}

// This file's helpers deliberately build every test fixture locally
// (plain httptest servers bound to distinct 127.0.0.x loopback
// addresses, plus dns.NewFakeResolver -- the exact same pattern
// internal/crawler's own tests already use, see crawler_test.go) rather
// than depending on the lab package. internal/auth must stay
// independently testable without the lab (production code never
// imports lab -- see docs/lab-isolation-review.md), and a package's own
// unit/adversarial tests are production code for this purpose.

// newIPServer starts an httptest server bound to a specific loopback IP
// (rather than the default 127.0.0.1 every httptest.NewServer call
// would otherwise share), so multiple fixture "hosts" in one test can
// have genuinely distinct addresses -- required for scope rules and
// redirect-target tests to mean anything.
func newIPServer(t *testing.T, ip string, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func serverIP(t *testing.T, srv *httptest.Server) net.IP {
	t.Helper()
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("parse IP %q", host)
	}
	return ip
}

func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

// fakeResolver returns a dns.Resolver mapping each hostname key in
// hosts to the given *httptest.Server's own bound IP.
func fakeResolver(t *testing.T, hosts map[string]*httptest.Server) *dns.FakeResolver {
	t.Helper()
	r := dns.NewFakeResolver()
	for host, srv := range hosts {
		r.Hosts[host] = []net.IP{serverIP(t, srv)}
	}
	return r
}

// allowAllValidator lets every check through -- used only by tests that
// are not themselves testing scope enforcement (mirrors
// internal/crawler/crawler_test.go's own identical helper).
type allowAllValidator struct{}

func (allowAllValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}
func (allowAllValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}
func (allowAllValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}

// realValidator builds a genuine internal/scope.Validator from rules,
// with reserved-range denial disabled (every test fixture here lives on
// 127.0.0.0/8) -- used by every test that specifically exercises scope
// enforcement, so those tests run against the SAME validator logic
// production code uses, not a mock of it.
func realValidator(rules ...models.ScopeRule) scope.Validator {
	return scope.NewValidator(rules, true)
}

func allowHost(host string) models.ScopeRule {
	return models.ScopeRule{Value: host, Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}
}

func newDialer(resolver dns.Resolver, validator scope.Validator) *safedial.Dialer {
	return safedial.New(validator, resolver)
}

func deps(t *testing.T, resolver dns.Resolver, validator scope.Validator) Dependencies {
	t.Helper()
	return Dependencies{Dialer: newDialer(resolver, validator), Validator: validator}
}
