package traversalactive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/traversal"
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

// --- shared test helpers (mirrors internal/detectors/cmdinjectionactive/ssrfactive) ---

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
		URL: srv.URL + "/?" + param + "=readme.txt", Path: "/", Method: method,
		Parameter: param, ParameterLocation: location,
	}
}

func pathTargetFor(t *testing.T, srv *httptest.Server, param, urlPath string, segmentIndex int) detection.Target {
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
		URL: srv.URL + urlPath, Path: urlPath, Method: nethttp.MethodGet,
		Parameter: param, ParameterLocation: "path", PathSegmentIndex: segmentIndex,
	}
}

// testCase/testFS/testMarker mirror the real lab's own
// travSynthFS/registerPathTraversalAPI shape exactly (path.Clean(path.Join("public", file)),
// public/protected split, the same known marker string), duplicated
// here since these packages share no test helpers.
const testMarker = "PATH_TRAVERSAL_SECRET_MARKER"

var testFS = map[string]string{
	"public":                      "index of public/",
	"public/readme.txt":           "hello from the fixture",
	"protected/secret-marker.txt": testMarker,
}

func vulnerableHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	file := r.URL.Query().Get("file")
	resolved := path.Clean(path.Join("public", file))
	content, ok := testFS[resolved]
	w.Header().Set("Content-Type", "text/plain")
	if !ok {
		w.WriteHeader(nethttp.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	fmt.Fprint(w, content)
}

func safeHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	file := r.URL.Query().Get("file")
	resolved := path.Clean(path.Join("public", file))
	w.Header().Set("Content-Type", "text/plain")
	if resolved != "public" && !strings.HasPrefix(resolved, "public/") {
		w.WriteHeader(nethttp.StatusForbidden)
		fmt.Fprint(w, "forbidden")
		return
	}
	content, ok := testFS[resolved]
	if !ok {
		w.WriteHeader(nethttp.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	fmt.Fprint(w, content)
}

func testCase() traversal.TraversalCase {
	return traversal.TraversalCase{RelativePath: "../protected/secret-marker.txt", Marker: testMarker}
}

// --- Metadata / eligibility ------------------------------------------------

func TestMetadata_HasExpectedIdentity(t *testing.T) {
	meta := New(nil).Metadata()
	if meta.ID != "path-traversal-active" {
		t.Errorf("ID = %q, want path-traversal-active", meta.ID)
	}
	if meta.Name == "" || meta.Category == "" {
		t.Error("Name/Category must not be empty")
	}
}

func TestEligible_QueryGET_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "file", ParameterLocation: "query", Method: nethttp.MethodGet}
	if !New(nil).Eligible(tgt) {
		t.Error("expected eligible for a GET, file-path-shaped query parameter")
	}
}

func TestEligible_QueryPOST_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "file", ParameterLocation: "query", Method: nethttp.MethodPost}
	if New(nil).Eligible(tgt) {
		t.Error("a POST query-location target should not be eligible")
	}
}

func TestEligible_FormBodyPathAnyMethod_True(t *testing.T) {
	for _, loc := range []string{"form", "body", "path"} {
		for _, method := range []string{nethttp.MethodGet, nethttp.MethodPost, nethttp.MethodPut} {
			tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "file", ParameterLocation: loc, Method: method}
			if !New(nil).Eligible(tgt) {
				t.Errorf("expected eligible for a %s %s-location target", method, loc)
			}
		}
	}
}

func TestEligible_PathInferredSuffix_True(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: "file_value", ParameterLocation: "path", Method: nethttp.MethodGet}
	if !New(nil).Eligible(tgt) {
		t.Error("expected eligible for the path-inferred 'file_value' name")
	}
}

func TestEligible_NonFilePathName_False(t *testing.T) {
	for _, name := range []string{"page", "id", "sort", "note_id", "url"} {
		tgt := detection.Target{Kind: detection.TargetKindEndpoint, Parameter: name, ParameterLocation: "query", Method: nethttp.MethodGet}
		if New(nil).Eligible(tgt) {
			t.Errorf("%q should not be eligible (not file-path-shaped)", name)
		}
	}
}

func TestEligible_NoParameter_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindEndpoint, ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil).Eligible(tgt) {
		t.Error("a target with no Parameter must never be eligible")
	}
}

func TestEligible_HTTPServiceKind_False(t *testing.T) {
	tgt := detection.Target{Kind: detection.TargetKindHTTPService, Parameter: "file", ParameterLocation: "query", Method: nethttp.MethodGet}
	if New(nil).Eligible(tgt) {
		t.Error("an HTTPService-kind target must never be eligible")
	}
}

// --- Detect: nil/empty cases -----------------------------------------------

func TestDetect_NilCases_Skipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New(nil).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeSkipped {
		t.Fatalf("Outcome = %s, want skipped (nil cases)", result.Outcome)
	}
}

// --- Detect: positive/negative, mirroring the real lab fixtures --------

func TestDetect_Vulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding", result.Outcome)
	}
	f := result.Findings[0]
	if f.VulnerabilityType != "path_traversal" {
		t.Errorf("VulnerabilityType = %q, want path_traversal", f.VulnerabilityType)
	}
	if f.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + probe), got %d", len(f.Evidence))
	}
}

func TestDetect_SafeContained_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(safeHandler))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (containment-checked endpoint)", result.Outcome)
	}
}

func TestDetect_Sanitized_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(file, "..") {
			w.WriteHeader(nethttp.StatusForbidden)
			fmt.Fprint(w, "forbidden: traversal sequence rejected")
			return
		}
		resolved := path.Clean(path.Join("public", file))
		content, ok := testFS[resolved]
		if !ok {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (\"..\" blocklisted)", result.Outcome)
	}
}

func TestDetect_ByIDNoPathConstruction_NoFinding(t *testing.T) {
	byID := map[string]string{"1": "hello"}
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		content, ok := byID[id]
		if !ok {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	tgt.URL = srv.URL + "/?file=1"
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (opaque ID key, never path-joined)", result.Outcome)
	}
}

func TestDetect_ReflectionOnly_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := r.URL.Query().Get("file")
		fmt.Fprintf(w, "Requested file: %s", file)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (pure reflection, never a real file lookup)", result.Outcome)
	}
}

func TestDetect_GenericResponse_NoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("Outcome = %s, want no_finding (generic, constant response)", result.Outcome)
	}
}

// --- Detect: form/JSON/path locations ------------------------------------

func TestDetect_FormLocationVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := r.ParseForm(); err != nil {
			nethttp.Error(w, "bad form", nethttp.StatusBadRequest)
			return
		}
		file := r.FormValue("file")
		resolved := path.Clean(path.Join("public", file))
		content, ok := testFS[resolved]
		w.Header().Set("Content-Type", "text/plain")
		if !ok {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "form", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
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
			File string `json:"file"`
		}
		_ = jsonDecode(r, &payload) // empty baseline body tolerated -- see cmdinjectionactive's own identical precedent
		resolved := path.Clean(path.Join("public", payload.File))
		content, ok := testFS[resolved]
		w.Header().Set("Content-Type", "text/plain")
		if !ok {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "body", nethttp.MethodPost)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %s, want finding for a vulnerable JSON body parameter", result.Outcome)
	}
}

func TestDetect_PathSegmentVulnerable_Finding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file := strings.TrimPrefix(r.URL.Path, "/download/")
		resolved := path.Clean(path.Join("public", file))
		content, ok := testFS[resolved]
		w.Header().Set("Content-Type", "text/plain")
		if !ok {
			w.WriteHeader(nethttp.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	tgt := pathTargetFor(t, srv, "file", "/download/readme.txt", 1)
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
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

	tgt := targetFor(t, srv, "file", "query", nethttp.MethodGet)
	x := newExecutor(false, detection.ExecutorConfig{})
	result, err := New([]traversal.TraversalCase{testCase()}).Detect(context.Background(), tgt, x)
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
