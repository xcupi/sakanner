package sstiactive

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

// --- Test-local fake template evaluator ---------------------------------
//
// Mirrors the lab's own independent simulation (never imported across
// packages, following every prior detector's own established
// precedent, e.g. sqliSimulateQuery living only in lab/harness_vuln.go)
// -- recognizes ONLY the 4 fixed "NUMBER*NUMBER" delimiter shapes this
// package's own templateVariants produces, never a real template
// engine, never arbitrary code.

var templatePatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"jinja2/twig/mustache", regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)},
	{"freemarker/jsp-el/thymeleaf", regexp.MustCompile(`\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}`)},
	{"ruby/jsf", regexp.MustCompile(`#\{\s*(\d+)\s*\*\s*(\d+)\s*\}`)},
	{"erb/jsp-scriptlet", regexp.MustCompile(`<%=\s*(\d+)\s*\*\s*(\d+)\s*%>`)},
}

func sstiSimulateRender(input string) (rendered string, ok bool) {
	for _, p := range templatePatterns {
		if m := p.re.FindStringSubmatch(input); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			return strconv.Itoa(a * b), true
		}
	}
	return "", false
}

// --- Fixture handlers --------------------------------------------------

func vulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	name := r.FormValue("name")
	if result, ok := sstiSimulateRender(name); ok {
		fmt.Fprintf(w, "Hello, %s!", result)
		return
	}
	fmt.Fprintf(w, "Hello, %s!", html.EscapeString(name))
}

func vulnerableJSONHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	var payload struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload) // tolerate empty/malformed body -- the JSON baseline probe has none seeded
	if result, ok := sstiSimulateRender(payload.Name); ok {
		fmt.Fprintf(w, "Hello, %s!", result)
		return
	}
	fmt.Fprintf(w, "Hello, %s!", html.EscapeString(payload.Name))
}

func vulnerablePathHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/greet/"))
	if result, ok := sstiSimulateRender(name); ok {
		fmt.Fprintf(w, "Hello, %s!", result)
		return
	}
	fmt.Fprintf(w, "Hello, %s!", html.EscapeString(name))
}

func safeHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	name := r.FormValue("name")
	fmt.Fprintf(w, "Hello, %s!", html.EscapeString(name))
}

func genericHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	fmt.Fprint(w, "Welcome to the site.")
}

// --- Test helpers --------------------------------------------------------

type fakeValidator struct{ allowed bool }

func (f *fakeValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *fakeValidator) check() (scope.Decision, error) {
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

func newExecutor(allowed bool, cfg detection.ExecutorConfig) *detection.Executor {
	return detection.NewExecutor(&fakeValidator{allowed: allowed}, dns.NewFakeResolver(), cfg)
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
		Path: "/greet", Method: method, Parameter: param, ParameterLocation: location,
	}
}

func pathTargetFor(t *testing.T, srv *httptest.Server, param, path string, segIdx int, method string) detection.Target {
	t.Helper()
	tgt := targetFor(t, srv, param, "path", method)
	tgt.Path = path
	tgt.PathSegmentIndex = segIdx
	return tgt
}

// --- Metadata / Eligible ------------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	md := New().Metadata()
	if md.ID != ID {
		t.Errorf("ID = %q, want %q", md.ID, ID)
	}
	if md.Category != "injection" {
		t.Errorf("Category = %q, want injection", md.Category)
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "name", ParameterLocation: "query", Method: "GET"}
	if !(Detector{}).Eligible(tgt) {
		t.Error("expected query+GET+name to be eligible")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "name", ParameterLocation: "query", Method: "POST"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected query+POST to be ineligible")
	}
}

func TestEligible_FormBodyPathAnyMethod_True(t *testing.T) {
	for _, loc := range []string{"form", "body", "path"} {
		for _, method := range []string{"GET", "POST", "PUT"} {
			tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "comment", ParameterLocation: loc, Method: method}
			if !(Detector{}).Eligible(tgt) {
				t.Errorf("expected %s/%s to be eligible", loc, method)
			}
		}
	}
}

func TestEligible_NoNameHeuristicGate_AnyParameterName_True(t *testing.T) {
	for _, name := range []string{"name", "comment", "message", "id", "q", "arbitrary_field"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: name, ParameterLocation: "query", Method: "GET"}
		if !(Detector{}).Eligible(tgt) {
			t.Errorf("expected parameter name %q to be eligible (SSTI has no name-heuristic gate)", name)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: "GET"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected empty Parameter to be ineligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "name", ParameterLocation: "query", Method: "GET"}
	if (Detector{}).Eligible(tgt) {
		t.Error("expected TargetKindHTTPService to be ineligible")
	}
}

// --- Detect: positive/negative -------------------------------------------

func TestDetect_Vulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "ssti" {
		t.Errorf("VulnerabilityType = %q, want ssti", f.VulnerabilityType)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("len(Evidence) = %d, want 2", len(f.Evidence))
	}
}

func TestDetect_Safe_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(safeHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a safe, always-escaped-reflection endpoint was flagged")
	}
}

func TestDetect_Generic_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(genericHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a constant-response endpoint was flagged")
	}
}

// --- Detect: form / JSON / path locations ---------------------------------

func TestDetect_FormLocationVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()
	tgt := targetFor(t, srv, "name", "form", "POST")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
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
	tgt := targetFor(t, srv, "name", "body", "POST")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
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
	tgt := pathTargetFor(t, srv, "name_value", "/greet/x", 1, "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
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
	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(false, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for an out-of-scope target")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: a finding was produced for an out-of-scope target")
	}
}
