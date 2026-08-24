package openredirectactive

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// testDestination is the operator-configured, out-of-scope destination
// every test in this package uses -- an unresolvable, non-existent
// host is deliberately fine: hostConditionalValidator denies it, so
// the underlying client's CheckRedirect stops the chain BEFORE any
// dial to it is ever attempted (mirroring the real lab's own
// safedial-truncation behavior exactly, see
// docs/phase-3-28-open-redirect-active.md section 1.3).
const testDestination = "http://external.redirect.test/sakanner-lab-redirect-marker"

// hostConditionalValidator allows only an explicit set of hostnames --
// used throughout this package's own tests (not just adversarial
// ones) because THIS detector's entire proof mechanism depends on the
// configured destination being genuinely out of scope, unlike
// traversal/cmdinjection where scope was a secondary adversarial
// concern.
type hostConditionalValidator struct{ allowedHosts map[string]bool }

func (v *hostConditionalValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	if v.allowedHosts[host] {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny: " + host}, nil
}
func (v *hostConditionalValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true, Reason: "test allow (IP-level, unused by this test)"}, nil
}
func (v *hostConditionalValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return v.CheckHost(ctx, hostname)
}

// newExecutor builds an Executor whose scope allows only srv's own
// host -- the configured destination host is always denied, exactly
// matching the real "target in scope, destination never in scope"
// production/lab scenario.
func newExecutor(srv *httptest.Server, cfg detection.ExecutorConfig) *detection.Executor {
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	v := &hostConditionalValidator{allowedHosts: map[string]bool{host: true}}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 5
	}
	return detection.NewExecutor(v, dns.NewFakeResolver(), cfg)
}

func targetFor(t *testing.T, srv *httptest.Server, param, location, method string) detection.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("could not parse listener IP %q", host)
	}
	return detection.Target{
		Kind: detection.TargetKindEndpoint, Host: host, IP: ip, Port: port, Scheme: "http",
		Path: "/redirect", Method: method, Parameter: param, ParameterLocation: location,
	}
}

func pathTargetFor(t *testing.T, srv *httptest.Server, param, path string, segIdx int, method string) detection.Target {
	t.Helper()
	tgt := targetFor(t, srv, param, "path", method)
	tgt.Path = path
	tgt.PathSegmentIndex = segIdx
	return tgt
}

// --- Fixture handlers --------------------------------------------------

func vulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := r.FormValue("next")
	if next == "" {
		w.Write([]byte("ok"))
		return
	}
	nethttp.Redirect(w, r, next, nethttp.StatusFound)
}

func vulnerableJSONHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	var payload struct {
		Next string `json:"next"`
	}
	_ = readJSON(r, &payload) // tolerate empty/malformed body -- the JSON baseline probe has none seeded
	if payload.Next == "" {
		w.Write([]byte("ok"))
		return
	}
	nethttp.Redirect(w, r, payload.Next, nethttp.StatusFound)
}

func vulnerablePathHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := strings.TrimPrefix(r.URL.Path, "/redirect/path/")
	if next == "" {
		w.Write([]byte("ok"))
		return
	}
	nethttp.Redirect(w, r, next, nethttp.StatusFound)
}

func safeOriginHandler(origin string) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		next := r.FormValue("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		// A relative path is safe ONLY if it is not ALSO
		// protocol-relative ("//host/..." starts with "/" but is a
		// full authority change in every browser and in
		// url.ResolveReference) -- a naive "starts with /" check
		// alone is a real, common bypass this fixture must not
		// reproduce.
		isRelative := strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//")
		if isRelative || strings.HasPrefix(next, origin) {
			nethttp.Redirect(w, r, next, nethttp.StatusFound)
			return
		}
		nethttp.Redirect(w, r, "/dashboard", nethttp.StatusFound)
	}
}

func allowlistHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := r.FormValue("next")
	allowed := map[string]bool{"/dashboard": true, "/profile": true}
	if !allowed[next] {
		next = "/dashboard"
	}
	nethttp.Redirect(w, r, next, nethttp.StatusFound)
}

func relativeOnlyHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := r.FormValue("next")
	if next == "" {
		w.Write([]byte("ok"))
		return
	}
	if idx := strings.Index(next, "://"); idx >= 0 {
		next = next[idx+3:]
		if s := strings.IndexByte(next, '/'); s >= 0 {
			next = next[s:]
		} else {
			next = "/"
		}
	}
	if strings.HasPrefix(next, "//") {
		next = "/" + strings.TrimLeft(next, "/")
	}
	nethttp.Redirect(w, r, next, nethttp.StatusFound)
}

func reflectOnlyHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := r.FormValue("next")
	fmt.Fprintf(w, "you will be redirected to: %s", next)
}

func trackingDecoyHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	next := r.FormValue("next")
	nethttp.Redirect(w, r, "/dashboard?ref="+next, nethttp.StatusFound)
}

func readJSON(r *nethttp.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Metadata / Eligible ------------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	md := New(testDestination).Metadata()
	if md.ID != ID {
		t.Errorf("ID = %q, want %q", md.ID, ID)
	}
	if md.Category != "broken_access_control" {
		t.Errorf("Category = %q, want broken_access_control", md.Category)
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "next", ParameterLocation: "query", Method: "GET"}
	if !(Detector{}).Eligible(tgt) {
		t.Error("expected query+GET+next to be eligible")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "next", ParameterLocation: "query", Method: "POST"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected query+POST to be ineligible")
	}
}

func TestEligible_FormBodyPathAnyMethod_True(t *testing.T) {
	for _, loc := range []string{"form", "body", "path"} {
		for _, method := range []string{"GET", "POST", "PUT"} {
			tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "redirect", ParameterLocation: loc, Method: method}
			if !(Detector{}).Eligible(tgt) {
				t.Errorf("expected %s/%s to be eligible", loc, method)
			}
		}
	}
}

func TestEligible_PathInferredSuffix_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "redirect_value", ParameterLocation: "path", Method: "GET"}
	if !(Detector{}).Eligible(tgt) {
		t.Error("expected path-inferred \"redirect_value\" to be eligible")
	}
}

func TestEligible_NonURLName_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "id", ParameterLocation: "query", Method: "GET"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected a non-URL-shaped name to be ineligible")
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: "GET"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected empty Parameter to be ineligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "next", ParameterLocation: "query", Method: "GET"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected TargetKindHTTPService to be ineligible")
	}
}

// --- Detect: no config ---------------------------------------------------

func TestDetect_NoDestination_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New("").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Errorf("Outcome = %s, want skipped", result.Outcome)
	}
}

// --- Detect: positive/negative -------------------------------------------

func TestDetect_Vulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "open_redirect" {
		t.Errorf("VulnerabilityType = %q, want open_redirect", f.VulnerabilityType)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("len(Evidence) = %d, want 2", len(f.Evidence))
	}
}

func TestDetect_SafeOrigin_NoFinding(t *testing.T) {
	mux := nethttp.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/redirect", safeOriginHandler(srv.URL))

	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: safe-origin-validated endpoint was flagged")
	}
}

func TestDetect_Allowlist_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(allowlistHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: allowlisted endpoint was flagged")
	}
}

func TestDetect_RelativeOnly_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(relativeOnlyHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: relative-only endpoint was flagged")
	}
}

func TestDetect_ReflectOnly_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(reflectOnlyHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: reflection-only (no redirect) endpoint was flagged")
	}
}

func TestDetect_TrackingDecoy_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(trackingDecoyHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a same-origin redirect whose Location merely CONTAINS the payload as a query-string decoration was flagged")
	}
}

// --- Detect: form / JSON / path locations ---------------------------------

func TestDetect_FormLocationVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "form", "POST")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
}

func TestDetect_JSONBodyVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableJSONHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "body", "POST")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
}

func TestDetect_PathSegmentVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerablePathHandler))
	defer srv.Close()
	tgt := pathTargetFor(t, srv, "path_value", "/redirect/path/x", 2, "GET")
	x := newExecutor(srv, detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
}

// --- Detect: scope --------------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "next", "query", "GET")
	v := &hostConditionalValidator{allowedHosts: map[string]bool{}}
	x := detection.NewExecutor(v, dns.NewFakeResolver(), detection.ExecutorConfig{})
	result, err := New(testDestination).Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for an out-of-scope target")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a finding was produced for an out-of-scope target")
	}
}
