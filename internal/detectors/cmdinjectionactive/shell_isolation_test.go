package cmdinjectionactive

import (
	"context"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

// This file exists specifically for task section 1's CRITICAL SAFETY
// PROPERTY: the scanner must never interpret target-controlled input
// as a local shell command. Mirrors
// internal/detectors/cmdinjection/shell_isolation_test.go exactly,
// adapted to this package's own API.

// TestSourceNeverInvokesLocalShellOrExec is a static, belt-and-
// suspenders guarantee: this package's own .go source (excluding test
// files) never IMPORTS "os/exec" or "syscall" -- checked via go/parser
// against the actual parsed import declarations, never a naive
// substring search.
func TestSourceNeverInvokesLocalShellOrExec(t *testing.T) {
	forbiddenImports := map[string]bool{"os/exec": true, "syscall": true}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if forbiddenImports[importPath] {
				t.Errorf("%s imports %q -- this package must never invoke a local shell or command-execution API; every \"command\" it handles is HTTP request/response data only", name, importPath)
			}
		}
	}
}

// TestDetect_MaliciousParameterValue_NeverInvokesLocalShell runs
// Detect with a discovered parameter value shaped like an attempt to
// break out to a real local shell, from a temp, otherwise-empty
// working directory -- so any accidental local command execution
// would be immediately visible.
func TestDetect_MaliciousParameterValue_NeverInvokesLocalShell(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(oldWD)

	srv := httptest.NewServer(safeHandler())
	defer srv.Close()

	dangerous := []string{
		"; touch /tmp/sakanner-shell-isolation-canary",
		"$(touch pwned.txt)",
		"`rm -rf /tmp/whatever`",
		"; echo pwned > pwned-via-shell.txt",
		"127.0.0.1 && cat /etc/passwd",
	}

	for _, value := range dangerous {
		d := New()
		tgt := targetFor(t, srv, "host", "query", "GET")
		tgt.URL = srv.URL + "/?host=" + value
		x := newExecutor(true, detection.ExecutorConfig{})

		result, err := d.Detect(context.Background(), tgt, x)
		if err != nil {
			t.Errorf("Detect(%q): unexpected error %v -- must degrade gracefully, never invoke a local shell", value, err)
			continue
		}
		if result.Outcome == detection.OutcomeFinding {
			t.Errorf("Detect(%q): got a finding, want none", value)
		}
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir(tmp): %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp working directory has %d entries after Detect, want 0 -- Detect must never create, read, or otherwise touch local files, and certainly never execute a local shell command", len(entries))
	}
}

// TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP
// is the SAME guarantee, but against a fixture that DOES confirm --
// proving that even a genuinely successful detection never involves
// anything beyond building and sending an ordinary HTTP request.
func TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(oldWD)

	srv := httptest.NewServer(vulnerableHandler(unixPattern))
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding (sanity check that this fixture is genuinely detectable)", result.Outcome)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir(tmp): %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp working directory has %d entries after a CONFIRMED finding, want 0 -- confirmation happens entirely by inspecting an HTTP response body, never by executing anything locally", len(entries))
	}
}

// TestEligible_NeverInspectsParameterValue confirms Eligible only ever
// looks at the parameter's NAME -- never its value.
func TestEligible_NeverInspectsParameterValue(t *testing.T) {
	d := New()
	tgt := detection.Target{
		Kind: detection.TargetKindEndpoint, Method: "GET",
		Parameter: "host", ParameterLocation: "query",
		URL: "http://127.0.0.1/?host=" + "; rm -rf / --no-preserve-root",
	}
	if !d.Eligible(tgt) {
		t.Error("Eligible = false, want true -- eligibility must depend only on the parameter NAME, not its value")
	}
}
