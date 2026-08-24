package cmdinjectionactive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/scope"
)

func jsonDecode(r *nethttp.Request, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func pathSuffix(path, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

// --- shared test helpers (mirrors internal/detectors/ssrfactive/sqliactive) ---

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
		URL: srv.URL + "/?" + param + "=127.0.0.1", Path: "/", Method: method,
		Parameter: param, ParameterLocation: location,
	}
}

func pathTargetFor(t *testing.T, srv *httptest.Server, param, path string, segmentIndex int) detection.Target {
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
		URL: srv.URL + path, Path: path, Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "path", PathSegmentIndex: segmentIndex,
	}
}

// unixPattern/windowsPattern mirror lab/harness_vuln.go's own
// cmdInjectionPattern and this phase's own new Windows-style
// counterpart exactly (a pure Go regexp, no shell involved) -- see
// docs/phase-3-26-command-injection-active.md section 10.B for why
// ";" is deliberately excluded from the Windows grammar (real cmd.exe
// never treats it as a separator).
var unixPattern = regexp.MustCompile(`(?:;|\||&&)\s*` + labCommand + `\s+(\S+)`)
var windowsPattern = regexp.MustCompile(`(?:&{1,2}|\|)\s*` + labCommand + `\s+(\S+)`)

func vulnerableHandler(pattern *regexp.Regexp) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if m := pattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)", host)
	}
}

func safeHandler() nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		safe := regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)
		if !safe.MatchString(host) {
			w.WriteHeader(nethttp.StatusBadRequest)
			w.Write([]byte("invalid host: rejected"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", host)
	}
}

// --- Metadata / eligibility ------------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New().Metadata()
	if meta.ID != "command-injection-active" {
		t.Errorf("ID = %q, want command-injection-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "host", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New().Eligible(tgt) {
		t.Error("expected eligible for a GET, command-shaped query parameter")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "host", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New().Eligible(tgt) {
		t.Error("a POST query-location target should not be eligible")
	}
}

func TestEligible_FormBodyPathAnyMethod_True(t *testing.T) {
	for _, loc := range []string{"form", "body", "path"} {
		for _, method := range []string{nethttp.MethodGet, nethttp.MethodPost, nethttp.MethodPut} {
			tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "host", ParameterLocation: loc, Method: method}
			if !New().Eligible(tgt) {
				t.Errorf("expected eligible for a %s %s-location target", method, loc)
			}
		}
	}
}

func TestEligible_NonCommandName_False(t *testing.T) {
	for _, name := range []string{"page", "id", "sort", "note_id", "url"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: name, ParameterLocation: "query", Method: nethttp.MethodGet}
		if New().Eligible(tgt) {
			t.Errorf("%q should not be eligible (not command-shaped)", name)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "host", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New().Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

// --- Detect: positive/negative, mirroring the real lab fixtures --------

func TestDetect_UnixVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler(unixPattern))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (Unix-style separators)", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "command_injection" {
		t.Errorf("VulnerabilityType = %q, want command_injection", f.VulnerabilityType)
	}
	if f.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + probe), got %d", len(f.Evidence))
	}
}

func TestDetect_WindowsVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler(windowsPattern))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding (Windows-style separators: the pipe/double-ampersand/single-ampersand variants must confirm even though semicolon never matches)", result.Outcome)
	}
}

func TestDetect_SafeAllowlisted_NoFinding(t *testing.T) {
	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// The baseline (127.0.0.1) passes the allowlist, but every probe
	// value (containing a separator character) is rejected by it --
	// Detect must never produce a finding.
	if result.Outcome == detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want no_finding/skipped for a properly allowlisted endpoint", result.Outcome)
	}
}

func TestDetect_ReflectionOnly_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := r.URL.Query().Get("host")
		fmt.Fprintf(w, "Requested host: %s", host)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (pure reflection, never grammar-matched)", result.Outcome)
	}
}

func TestDetect_StaticMarkerPresent_NoFinding(t *testing.T) {
	// The bare marker prefix appears in EVERY response, but never
	// followed by a real per-probe token -- must never false-positive.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprintf(w, "PING normal response\n<!-- %sstatic-unrelated-text -->", markerPrefix)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (marker prefix present but never followed by THIS probe's own token)", result.Outcome)
	}
}

// --- Detect: form/JSON/path locations ------------------------------------

func TestDetect_FormLocationVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		host := r.FormValue("host")
		if m := unixPattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response", host)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable POST form parameter", result.Outcome)
	}
}

func TestDetect_JSONBodyVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var payload struct {
			Host string `json:"host"`
		}
		// Ignore the unmarshal error rather than rejecting -- the
		// BASELINE probe for JSON-body location has no seeded body at
		// all (unlike query/form, detection.NewMutationRequest has no
		// mechanism to pre-populate a JSON body from t.URL), so it
		// legitimately arrives empty; a real vulnerable endpoint would
		// tolerate that the same way this fixture does (mirrors
		// internal/detectors/sqliactive's own identical, already-
		// established test precedent).
		_ = jsonDecode(r, &payload)
		if m := unixPattern.FindStringSubmatch(payload.Host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response\n%s%s", payload.Host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response", payload.Host)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable JSON body parameter", result.Outcome)
	}
}

func TestDetect_PathSegmentVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host := pathSuffix(r.URL.Path, "/exec/")
		if m := unixPattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response\n%s%s", host, markerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response", host)
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "host", "/exec/127.0.0.1", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable path segment", result.Outcome)
	}
}

// --- Scope enforcement ---------------------------------------------------

func TestDetect_DeniedScope_ErrorsAndNoRequestsIssued(t *testing.T) {
	var hits int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits++
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "host", "query", nethttp.MethodGet)
	x := newExecutor(false, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err == nil {
		t.Fatal("expected an error for a denied-scope target")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a scope-denied target must never produce a finding")
	}
	if hits != 0 {
		t.Fatalf("SECURITY: server received %d requests despite a denied scope, want 0", hits)
	}
}
