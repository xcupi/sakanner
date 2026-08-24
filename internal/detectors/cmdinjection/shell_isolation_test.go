package cmdinjection

import (
	"context"
	"go/parser"
	"go/token"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

// This file exists specifically for section 20's CRITICAL SECURITY
// REQUIREMENT: the scanner must never interpret target-controlled
// input as a local shell command. See
// docs/phase-3-7-command-injection.md "Scanner shell isolation."

// TestSourceNeverInvokesLocalShellOrExec is a static, belt-and-
// suspenders guarantee: this package's own .go source (excluding test
// files, which are never part of the shipped binary) never IMPORTS
// "os/exec" or "syscall" -- checked via go/parser against the actual
// parsed import declarations, never a naive substring search (which
// would also flag this very sentence, since it mentions the package
// name in prose). This detector operates ENTIRELY over HTTP; there is
// no code path in it that could construct or run a local shell
// command, because there is no local command-execution capability of
// any kind.
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
// break out to a real local shell (as if a compromised/malicious recon
// result tried to feed this detector something dangerous), from a
// temp, otherwise-empty working directory -- so any accidental local
// command execution (e.g. writing a file, as `touch`/`> file` shell
// redirection would) would be immediately visible. Only HTTP requests
// to the fake server are ever expected to occur.
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
		tgt := targetFor(t, srv, "host", value)
		x := newExecutor(true, detection.ExecutorConfig{})

		result, err := d.Detect(context.Background(), tgt, x)
		if err != nil {
			t.Errorf("Detect(%q): unexpected error %v -- must degrade gracefully, never invoke a local shell", value, err)
			continue
		}
		// Every dangerous value is rejected by the SAFE fixture's
		// allowlist (400), so the legitimate-access reference itself
		// fails and Detect returns NoFinding without ever probing
		// further -- exactly the expected, safe behavior.
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

	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New()
	tgt := targetFor(t, srv, "host", "127.0.0.1")
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
// looks at the parameter's NAME -- never its value -- so a malicious
// value can never influence candidate SELECTION either, only what gets
// sent as an ordinary HTTP request body/query value once a candidate
// is already selected by name.
func TestEligible_NeverInspectsParameterValue(t *testing.T) {
	d := New()
	tgt := detection.Target{
		Kind: detection.TargetKindEndpoint, Method: nethttp.MethodGet,
		Parameter: "host", ParameterLocation: "query",
		URL: "http://127.0.0.1/?host=" + "; rm -rf / --no-preserve-root",
	}
	if !d.Eligible(tgt) {
		t.Error("Eligible = false, want true -- eligibility must depend only on the parameter NAME, not its value")
	}
}
